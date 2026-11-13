package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoginDeviceFlowSavesTokenOwnerOnly(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device":
			_, _ = w.Write([]byte(`{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"/device","verification_uri_complete":"/device?code=ABCD-EFGH","expires_in":60,"interval":1}`))
		case "/v1/auth/device/token":
			polls++
			if polls < 2 {
				_, _ = w.Write([]byte(`{"status":"pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"approved","token":"wtu_abc_secret","token_id":"t1","scopes":["bootstrap"],"expires_at":"2030-01-01T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "wtctl", "config.json")
	t.Setenv("WTCTL_CONFIG", cfg)
	t.Setenv("WT_API_KEY", "")
	var out bytes.Buffer
	// Real sleeps are 1 s each here; keep the test to two polls.
	if err := loginMain(context.Background(), []string{"--api", srv.URL, "--scope", "bootstrap", "--project", "prj_x"}, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), srv.URL+"/device?code=ABCD-EFGH") || !strings.Contains(out.String(), "ABCD-EFGH") {
		t.Fatalf("no approval URL: %s", out.String())
	}
	c, _, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	got := c.Contexts["default"]
	if got.Key != "wtu_abc_secret" || got.TokenID != "t1" || c.Current != "default" {
		t.Fatalf("saved %+v current %q", got, c.Current)
	}
	if st, err := os.Stat(cfg); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("config mode %v %v", st, err)
	}
	// logout removes the context even when the server cannot revoke.
	out.Reset()
	if err := logoutMain(context.Background(), nil, &out); err != nil {
		t.Fatal(err)
	}
	c, _, _ = loadConfig()
	if len(c.Contexts) != 0 || c.Current != "" {
		t.Fatalf("after logout %+v", c)
	}
}

func TestDeviceLoginDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/device" {
			_, _ = w.Write([]byte(`{"device_code":"dc","user_code":"X","verification_uri_complete":"https://x/device","expires_in":60,"interval":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()
	_, err := deviceLogin(context.Background(), srv.URL, "", &bytes.Buffer{}, func(time.Duration) {})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatal(err)
	}
}
