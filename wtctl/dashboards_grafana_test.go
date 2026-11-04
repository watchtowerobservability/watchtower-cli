package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGrafanaUIDsPages(t *testing.T) {
	var auth string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		n := 1
		if r.URL.Query().Get("page") == "1" {
			n = grafanaPage
		}
		fmt.Fprint(w, "[")
		for i := 0; i < n; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"uid":"u%d"}`, i)
		}
		fmt.Fprint(w, "]")
	}))
	defer s.Close()
	got, err := grafanaClient{base: s.URL, token: "t", http: s.Client()}.uids(context.Background())
	if err != nil || len(got) != grafanaPage+1 {
		t.Fatalf("%d %v", len(got), err)
	}
	if auth != "Bearer t" {
		t.Fatalf("auth %q", auth)
	}
}
