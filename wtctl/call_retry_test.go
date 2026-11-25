package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func retryServer(t *testing.T, codes ...int) (*httptest.Server, *[]*http.Request, *[]string) {
	t.Helper()
	var reqs []*http.Request
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs, bodies = append(reqs, r), append(bodies, string(b))
		code := 200
		if len(reqs) <= len(codes) {
			code = codes[len(reqs)-1]
		}
		if code == 503 {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs, &bodies
}

func TestCallRetries(t *testing.T) {
	var slept []time.Duration
	orig := callSleep
	t.Cleanup(func() { callSleep = orig })
	callSleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	ctx := context.Background()

	srv, reqs, _ := retryServer(t, 502, 503, 200)
	if err := call(ctx, http.MethodGet, srv.URL, "k", nil, nil); err != nil || len(*reqs) != 3 {
		t.Fatalf("GET: %v after %d requests", err, len(*reqs))
	}
	if len(slept) != 2 || slept[0] != time.Second || slept[1] != 7*time.Second {
		t.Fatalf("backoff / Retry-After: %v", slept)
	}

	srv, reqs, _ = retryServer(t, 502, 200)
	if err := call(ctx, http.MethodPost, srv.URL, "k", map[string]int{"a": 1}, nil); err == nil || len(*reqs) != 1 {
		t.Fatalf("POST must not retry: %v, %d requests", err, len(*reqs))
	}

	srv, reqs, bodies := retryServer(t, 520, 200)
	if err := call(ctx, http.MethodPatch, srv.URL, "k", map[string]int{"a": 1}, nil); err != nil || len(*reqs) != 2 {
		t.Fatalf("PATCH: %v, %d requests", err, len(*reqs))
	}
	k := (*reqs)[0].Header.Get("Idempotency-Key")
	if k == "" || k != (*reqs)[1].Header.Get("Idempotency-Key") || (*bodies)[0] != (*bodies)[1] || (*bodies)[1] == "" {
		t.Fatalf("key %q / bodies %q not reused across retries", k, *bodies)
	}

	srv, reqs, _ = retryServer(t, 502, 502, 502, 502, 502, 502)
	if err := call(ctx, http.MethodGet, srv.URL, "k", nil, nil); err == nil || len(*reqs) != 5 {
		t.Fatalf("gives up after 5: %v, %d", err, len(*reqs))
	}
}
