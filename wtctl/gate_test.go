package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func gateServer(t *testing.T, verdicts ...string) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if i >= len(verdicts) {
			i = len(verdicts) - 1
		}
		fmt.Fprintf(w, `{"data":[{"gate_name":"prod","env_id":"env_1","verdict":%q}]}`, verdicts[i])
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGateWaitExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		verdicts []string
		wait     bool
		timeout  time.Duration
		want     int
	}{
		{"pass", []string{"pass"}, false, time.Second, gatePass},
		{"fail", []string{"fail"}, false, time.Second, gateFail},
		{"pending then pass", []string{"pending", "pending", "pass"}, true, 5 * time.Second, gatePass},
		{"pending then fail", []string{"pending", "fail"}, true, 5 * time.Second, gateFail},
		{"pending times out", []string{"pending"}, true, 50 * time.Millisecond, gateTimeout},
		{"pending without wait", []string{"pending"}, false, time.Second, gateTimeout},
		{"insufficient data", []string{"insufficient_data"}, true, time.Second, gateTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := gateServer(t, c.verdicts...)
			o := gateOpts{api: srv.URL, key: "k", project: "prj_1", version: "1.0.0", wait: c.wait, timeout: c.timeout, poll: 10 * time.Millisecond}
			var out bytes.Buffer
			got, err := gateCheck(context.Background(), o, &out)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("exit %d, want %d\n%s", got, c.want, out.String())
			}
		})
	}
}
