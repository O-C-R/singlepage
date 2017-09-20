package singlepage

import (
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSinglePageApplicationServer(t *testing.T) {
	singlePageApplication, err := NewSinglepageApplication(SinglepageApplicationOptions{
		Root: "./root",
		ApplicationMatcher: func(path string) (bool, error) {
			return path == "/", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(singlePageApplication)
	defer server.Close()

	if os.Getenv("TEST_SERVER") == "1" {
		fmt.Println(server.URL)
		time.Sleep(time.Hour)
	}
}
