package singlepage

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

var testRequests = []struct {
	path, redirect, response string
}{
	{"/", "/", "application"},
	{"/index.html", "/", "application"},
	{"/application/", "/application", "application"},
	{"/application/index.html", "/application", "application"},
	{"/some/path/that/works", "/some/path/that/works", "application"},
	{"/static/js/index.js", "/static/js/index.js", "console.log('index.js')"},
}

func TestSinglePageApplicationServer(t *testing.T) {
	application, err := regexp.Compile(`^/(([\w-]+)(/[\w-]+)*)?$`)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(
		NewSinglePageApplication(http.Dir(`./root`), application))
	defer server.Close()

	for _, request := range testRequests {

		req, err := http.NewRequest("GET", server.URL+request.path, nil)
		if err != nil {
			t.Error(err)
			continue
		}

		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			continue
		}

		if response.Request.URL.Path != request.redirect {
			t.Errorf("unexpected redirect, %s (expected %s)", response.Request.URL.Path, request.redirect)
			continue
		}

		responseBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Error(err)
			continue
		}

		if !bytes.Equal(responseBytes, []byte(request.response)) {
			t.Errorf("unexpected response, %s (expected %s)", string(responseBytes), request.response)
		}
	}
}
