package singlepage

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	EncodingNone   = 0
	EncodingGzip   = iota
	EncodingBrotli = iota
)

func init() {
	mime.AddExtensionType(".json", "application/json")
	mime.AddExtensionType(".map", "application/json")
}

var (
	directoryError = errors.New("directory error")
)

type FileInfo struct {
	Path          string
	Etag          string
	IsDir         bool
	LongtermCache bool
}

type PathMatcher func(path string) (bool, error)

func DefaultApplicationMatcher(path string) (bool, error) {
	return true, nil
}

func DefaultLongtermMatcher(path string) (bool, error) {
	return false, nil
}

type SinglepageApplicationOptions struct {
	Root                 string
	ApplicationMatcher   PathMatcher
	LongtermMatcher      PathMatcher
	CacheControl         string
	LongtermCacheControl string
}

type SinglepageApplication struct {
	options           SinglepageApplicationOptions
	fileInfo          map[string]*FileInfo
	applicationRegexp *regexp.Regexp
}

func NewSinglepageApplication(options SinglepageApplicationOptions) (*SinglepageApplication, error) {
	if options.ApplicationMatcher == nil {
		options.ApplicationMatcher = DefaultApplicationMatcher
	}

	if options.LongtermMatcher == nil {
		options.LongtermMatcher = DefaultLongtermMatcher
	}

	sa := &SinglepageApplication{
		options:  options,
		fileInfo: make(map[string]*FileInfo),
	}

	root := filepath.Clean(options.Root)
	if err := filepath.Walk(root, func(path string, fileInfo os.FileInfo, err error) error {

		rootPath := strings.TrimPrefix(path, root)
		sa.fileInfo[rootPath] = &FileInfo{
			Path:  path,
			IsDir: fileInfo.IsDir(),
		}

		if fileInfo.IsDir() {
			return nil
		}

		longtermCache, err := options.LongtermMatcher(rootPath)
		if err != nil {
			return err
		}

		sa.fileInfo[rootPath].LongtermCache = longtermCache

		// Attempt to open the file.
		file, err := os.Open(path)
		if err != nil {
			return err
		}

		// Defer closing the file.
		defer file.Close()

		// Get the SHA1 hash value for the file.
		fileHash := sha1.New()
		if _, err := io.Copy(fileHash, file); err != nil {
			return err
		}

		// Set an ETag header based on the SHA1 hash.
		sa.fileInfo[rootPath].Etag = `"` + base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(fileHash.Sum(nil)) + `"`

		return nil
	}); err != nil {
		return nil, err
	}

	return sa, nil
}

func (sa *SinglepageApplication) openFileInfo(req *http.Request, name string) (*FileInfo, int, error) {
	fileInfo, ok := sa.fileInfo[name]
	if !ok {
		return nil, EncodingNone, os.ErrNotExist
	}

	if fileInfo.IsDir {
		return nil, EncodingNone, directoryError
	}

	var acceptEncodingBrotli, acceptEncodingGzip bool
	encodings := strings.Split(req.Header.Get("accept-encoding"), ",")
	for _, encoding := range encodings {
		switch strings.TrimSpace(encoding) {
		case "br":
			acceptEncodingBrotli = true
		case "gzip":
			acceptEncodingGzip = true
		}
	}

	if acceptEncodingBrotli {
		fileInfo, ok := sa.fileInfo[name+".br"]
		if ok {
			return fileInfo, EncodingBrotli, nil
		}
	}

	if acceptEncodingGzip {
		fileInfo, ok := sa.fileInfo[name+".gz"]
		if ok {
			return fileInfo, EncodingGzip, nil
		}
	}

	return fileInfo, EncodingNone, nil
}

func (sa *SinglepageApplication) serveFile(w http.ResponseWriter, req *http.Request, name string) error {
	fileInfo, encoding, err := sa.openFileInfo(req, name)
	if err != nil {
		return err
	}

	// Attempt to open the file.
	file, err := os.Open(fileInfo.Path)
	if err != nil {
		return err
	}

	// Defer closing the file.
	defer file.Close()

	// Set an ETag header.
	w.Header().Set("etag", fileInfo.Etag)

	// Set a Content-Encoding header.
	switch encoding {
	case EncodingBrotli:
		w.Header().Set("content-encoding", "br")
		w.Header().Set("vary", "accept-encoding")
	case EncodingGzip:
		w.Header().Set("content-encoding", "gzip")
		w.Header().Set("vary", "accept-encoding")
	}

	// Set a Cache-Control header.
	if fileInfo.LongtermCache {
		w.Header().Set("cache-control", sa.options.LongtermCacheControl)
	} else {
		w.Header().Set("cache-control", sa.options.CacheControl)
	}

	http.ServeContent(w, req, name, time.Time{}, file)
	return nil
}

func (sa *SinglepageApplication) serveAny(w http.ResponseWriter, req *http.Request, name string) error {

	// Attempt to serve the file.
	err := sa.serveFile(w, req, name)

	// If the file is a directory, attempt to serve an index.
	if err == directoryError {
		return sa.serveFile(w, req, name+"/index.html")
	}

	// If the file doesn't exist, but the URL path matches the application
	// regexp, attempt to serve the application index.
	if os.IsNotExist(err) {
		application, err := sa.options.ApplicationMatcher(req.URL.Path)
		if err != nil {
			return err
		}

		if application {
			return sa.serveFile(w, req, "/index.html")
		}
	}

	// Return any other error.
	return err
}

func (sa *SinglepageApplication) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// Only handle GET and HEAD requests.
	if !(req.Method == http.MethodGet || req.Method == http.MethodHead) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	name := req.URL.Path

	// Handle a request for index.html on the root level.
	if name == "/index.html" {
		w.Header().Set("cache-control", sa.options.CacheControl)
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	// Handle trailing slashes.
	if name != "/" && strings.HasSuffix(name, "/") {
		w.Header().Set("cache-control", sa.options.CacheControl)
		http.Redirect(w, req, strings.TrimSuffix(req.URL.Path, "/"), http.StatusFound)
		return
	}

	// Handle a request for a sub-directory index.
	if strings.HasSuffix(name, "/index.html") {
		w.Header().Set("cache-control", sa.options.CacheControl)
		http.Redirect(w, req, strings.TrimSuffix(req.URL.Path, "/index.html"), http.StatusFound)
		return
	}

	var err error
	if name == "/" {
		err = sa.serveFile(w, req, "/index.html")
	} else {
		err = sa.serveAny(w, req, name)
	}

	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
