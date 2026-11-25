package container

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSelectorMatch(t *testing.T) {
	svc := map[string]string{ComposeServiceLabel: "api"}
	for _, c := range []struct {
		s     Selector
		name  string
		image string
		lb    map[string]string
		want  bool
	}{
		{Selector{}, "x", "y", nil, true},
		{Selector{Names: []string{"^web-"}}, "web-1", "nginx", nil, true},
		{Selector{Names: []string{"^web-"}}, "db", "nginx", nil, false},
		{Selector{Images: []string{"nginx"}}, "a", "nginx:1.25", nil, true}, // glob matches the bare image
		{Selector{Images: []string{"ghcr.io/acme/*"}}, "a", "ghcr.io/acme/app:2", nil, true},
		{Selector{Images: []string{"re:^redis(:|$)"}}, "a", "redis:7", nil, true},
		{Selector{Images: []string{"redis"}}, "a", "postgres:17", nil, false},
		{Selector{Services: []string{"ap?"}}, "a", "i", svc, true},
		{Selector{Services: []string{"*"}}, "a", "i", nil, false},                        // no compose label at all
		{Selector{Names: []string{"a"}, Services: []string{"db"}}, "a", "i", svc, false}, // ANDed
	} {
		if err := c.s.Compile(); err != nil {
			t.Fatal(err)
		}
		if got := c.s.Match(c.name, c.image, c.lb); got != c.want {
			t.Errorf("%+v %s %s: got %v", c.s, c.name, c.image, got)
		}
	}
	if err := (&Selector{Names: []string{"("}}).Compile(); err == nil {
		t.Fatal("bad regexp accepted")
	}
}

func TestDockerOverTCPSelectsAndMapsForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			_, _ = w.Write([]byte(`[{"Id":"aaaaaaaaaaaaaaaa","Names":["/web-1"],"Image":"nginx:1","Labels":{"com.docker.compose.service":"web"}},
			{"Id":"bbbbbbbbbbbbbbbb","Names":["/db-1"],"Image":"postgres:17","Labels":{"com.docker.compose.service":"db"}}]`))
			return
		}
		w.WriteHeader(http.StatusForbidden) // a socket proxy without the endpoint
	}))
	defer srv.Close()
	d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	d.Select = Selector{Services: []string{"web"}}
	if err := d.Select.Compile(); err != nil {
		t.Fatal(err)
	}
	got, err := d.List(context.Background())
	if err != nil || len(got) != 1 || got[0].Name != "web-1" {
		t.Fatalf("list %v %v", got, err)
	}
	if _, err := d.Env(context.Background(), "aaaa"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a 403 must be ErrForbidden: %v", err)
	}
}

func TestDefaultHostHonoursDockerHost(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://socket-proxy:2375")
	if DefaultHost() != "tcp://socket-proxy:2375" {
		t.Fatal(DefaultHost())
	}
}
