package lsp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeAPI struct {
	mu       sync.Mutex
	requests []string // method, URL and body of every call
	srv      *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.String()+" "+body.String())
		f.mu.Unlock()
		fmt.Fprint(w, `{"data":[{"function":"Handle","count":10,"errors":4,"p50_ms":20,"p95_ms":120,
			"last_issue":{"id":"iss_1","title":"nil deref"},"trace_example":"abcd"}]}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

const goSrc = "package x\n\nfunc Handle() {}\n\nfunc other() {}\n"

// repo makes a root with watchtower.yaml and one Go file per given relative path.
func repo(t *testing.T, yaml string, files ...string) string {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "watchtower.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(root, f)
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		if err := os.WriteFile(p, []byte(goSrc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// session sends requests {method, params} with ids 1.. and returns results by id.
func session(t *testing.T, api *fakeAPI, root string, reqs ...[2]any) map[int]json.RawMessage {
	var in bytes.Buffer
	send := func(m map[string]any) {
		b, _ := json.Marshal(m)
		fmt.Fprintf(&in, "Content-Length: %d\r\n\r\n%s", len(b), b)
	}
	send(map[string]any{"jsonrpc": "2.0", "id": 100, "method": "initialize", "params": map[string]any{"rootPath": root}})
	for i, r := range reqs {
		send(map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": r[0], "params": r[1]})
	}
	var out bytes.Buffer
	s := NewServer(&Client{BaseURL: api.srv.URL, Key: "k"}, "https://wt.example", &out)
	if err := s.Serve(context.Background(), &in); err != nil {
		t.Fatal(err)
	}
	res := map[int]json.RawMessage{}
	rd := bufio.NewReader(&out)
	for {
		body, err := readFrame(rd)
		if err != nil {
			break
		}
		var m struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		_ = json.Unmarshal(body, &m)
		res[m.ID] = m.Result
	}
	return res
}

func lensReq(root, rel string) [2]any {
	return [2]any{"textDocument/codeLens", map[string]any{"textDocument": map[string]string{"uri": fileURI(filepath.Join(root, rel))}}}
}

func TestCodeLensForMappedFile(t *testing.T) {
	api := newFakeAPI(t)
	root := repo(t, "service: api\nproject: prj_1\n", "a.go")
	res := session(t, api, root, lensReq(root, "a.go"))
	var lenses []codeLens
	if err := json.Unmarshal(res[1], &lenses); err != nil {
		t.Fatal(err)
	}
	if len(lenses) != 1 || lenses[0].Range.Start.Line != 2 {
		t.Fatalf("want one lens on line 2, got %+v", lenses)
	}
	if got := lenses[0].Command.Title; got != "p95 120 ms · 4 errors/24h" {
		t.Fatalf("title %q", got)
	}
	if lenses[0].Command.Command != cmdOpenIssue {
		t.Fatalf("command %q", lenses[0].Command.Command)
	}
}

func TestNoLensForUnmappedFile(t *testing.T) {
	api := newFakeAPI(t)
	root := repo(t, "service: api\nproject: prj_1\npath_prefixes: [svc/api]\n", "other/a.go")
	res := session(t, api, root, lensReq(root, "other/a.go"))
	if strings.TrimSpace(string(res[1])) != "[]" {
		t.Fatalf("want empty lens list, got %s", res[1])
	}
	if len(api.requests) != 0 {
		t.Fatalf("unmapped file must not call the API: %v", api.requests)
	}
}

func TestHoverShowsLatestIssue(t *testing.T) {
	api := newFakeAPI(t)
	root := repo(t, "service: api\nproject: prj_1\n", "a.go")
	uri := fileURI(filepath.Join(root, "a.go"))
	res := session(t, api, root,
		[2]any{"textDocument/hover", map[string]any{"textDocument": map[string]string{"uri": uri}, "position": map[string]int{"line": 2, "character": 6}}},
		[2]any{"workspace/executeCommand", map[string]any{"command": cmdOpenTrace, "arguments": []string{"prj_1", "abcd"}}},
	)
	h := string(res[1])
	for _, want := range []string{"nil deref", "https://wt.example/projects/prj_1/issues/iss_1", "Slowest trace"} {
		if !strings.Contains(h, want) {
			t.Fatalf("hover lacks %q: %s", want, h)
		}
	}
	if string(res[2]) != `"https://wt.example/projects/prj_1/traces/abcd"` {
		t.Fatalf("trace url %s", res[2])
	}
}

func TestPathPrefixMapping(t *testing.T) {
	c := &Config{Service: "api", PathPrefixes: []string{"svc/api/", "lib"}}
	for rel, want := range map[string]bool{
		"svc/api/x.go": true, "lib/a/b.go": true, "svc/apix/x.go": false, "other/x.go": false, "lib": true,
	} {
		if _, ok := c.ServiceFor(rel); ok != want {
			t.Errorf("%s: got %v want %v", rel, ok, want)
		}
	}
	if _, ok := (&Config{Service: "api"}).ServiceFor("any/x.go"); !ok {
		t.Error("no prefixes maps the whole repo")
	}
}

func TestFunctionRegexPerLanguage(t *testing.T) {
	cases := map[string]struct{ src, want string }{
		"a.go":        {"func (s *S) Handle(x int) {}", "Handle"},
		"a.rs":        {"    pub async fn run_it() {}", "run_it"},
		"a.ts":        {"export async function load() {}", "load"},
		"b.js":        {"const save = async (x) => {}", "save"},
		"a.py":        {"    async def fetch(self):", "fetch"},
		"A.java":      {"  public static void main(String[] a) {", "main"},
		"A.cs":        {"    public async Task<int> Run(int x)", "Run"},
		"A.kt":        {"    private suspend fun String.load(id: Int): X {", "load"},
		"B.kt":        {"fun main() {", "main"},
		"notes.txt":   {"func nope()", ""},
		"a.go-no-ext": {"func nope()", ""},
	}
	for name, c := range cases {
		got := Functions(name, c.src)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: want none, got %v", name, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Name != c.want {
			t.Errorf("%s: got %v want %s", name, got, c.want)
		}
	}
}

func TestNoSourceSentToServer(t *testing.T) {
	api := newFakeAPI(t)
	root := repo(t, "service: api\nproject: prj_1\n", "a.go")
	session(t, api, root, lensReq(root, "a.go"))
	if len(api.requests) == 0 {
		t.Fatal("expected an API call")
	}
	for _, r := range api.requests {
		if !strings.HasPrefix(r, "GET /v1/projects/prj_1/code-stats?") {
			t.Fatalf("unexpected request %s", r)
		}
		// request carries names and path only; neither the body of a function nor the file text
		if strings.Contains(r, "package x") || strings.Contains(r, "func%20") || strings.HasSuffix(strings.TrimSpace(r), "}") {
			t.Fatalf("source leaked in %s", r)
		}
		if !strings.Contains(r, "functions=Handle%2Cother") || !strings.Contains(r, "file=a.go") {
			t.Fatalf("want path and names only: %s", r)
		}
	}
}

// fileURI builds a file URI; Windows drive paths need file:///C:/...
func fileURI(p string) string {
	return "file://" + map[bool]string{true: "", false: "/"}[strings.HasPrefix(filepath.ToSlash(p), "/")] + filepath.ToSlash(p)
}

func TestUriPathWindowsStyle(t *testing.T) {
	for in, want := range map[string]string{"file:///C:/a/b.go": "C:/a/b.go", "file:///c%3A/a/b.go": "c:/a/b.go", "file:///a/b.go": "/a/b.go"} {
		if got := filepath.ToSlash(uriPath(in)); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestLogLensAndHover(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		if strings.HasSuffix(r.URL.Path, "/logs/search") {
			body = b.String()
			fmt.Fprint(w, `{"data":[{"body":"disk full","severity_text":"ERROR"},{"body":"retrying","severity_text":"WARN"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "watchtower.yaml"), []byte("service: api\nproject: prj_1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "a.go"), []byte("package x\n\nfunc Handle() {\n\tlog.Printf(\"hi\")\n}\n"), 0o600)
	uri := fileURI(filepath.Join(root, "a.go"))
	var out bytes.Buffer
	var in bytes.Buffer
	for i, m := range [][2]any{{"initialize", map[string]any{"rootPath": root}},
		{"textDocument/codeLens", map[string]any{"textDocument": map[string]string{"uri": uri}}},
		{"textDocument/hover", map[string]any{"textDocument": map[string]string{"uri": uri}, "position": map[string]int{"line": 3, "character": 2}}},
		{"workspace/executeCommand", map[string]any{"command": cmdOpenLogs, "arguments": []string{"prj_1", "api", "a.go", "4"}}}} {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": m[0], "params": m[1]})
		fmt.Fprintf(&in, "Content-Length: %d\r\n\r\n%s", len(b), b)
	}
	s := NewServer(&Client{BaseURL: srv.URL, Key: "k"}, "https://wt.example", &out)
	if err := s.Serve(context.Background(), &in); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"2 log lines/24h", cmdOpenLogs, "disk full", "Open in Logs", "code.filepath", "/projects/prj_1/logs?q="} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
	if !strings.Contains(body, `"value":"4"`) || !strings.Contains(body, `"services":["api"]`) {
		t.Fatalf("search body %s", body)
	}
	if strings.Contains(body, "log.Printf") {
		t.Fatal("source leaked")
	}
}

func TestLogSites(t *testing.T) {
	got := LogSites("a.py", "x = 1\nlogger.info('a')\nlogging.error(x)\n", 10)
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("got %v", got)
	}
	if len(LogSites("a.txt", "log.Info(", 5)) != 0 {
		t.Fatal("unsupported ext")
	}
}

func TestLiteralTemplate(t *testing.T) {
	for in, want := range map[string]string{
		`log.Printf("payment failed for user %s, retrying", id)`: "payment failed for user",
		`logger.info("Order {} shipped late", o)`:                "shipped late",
		`log.Println("ok")`: "",
		`foo()`:             "",
		"console.error(`cache miss ${key} in region`)": "cache miss",
	} {
		if got := Literal(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestLogsFallbackToTemplateAndCache(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		bodies = append(bodies, b.String())
		if strings.Contains(b.String(), `"text":"payment failed"`) {
			fmt.Fprint(w, `{"data":[{"body":"payment failed","severity_text":"ERROR"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Key: "k"}
	for i := 0; i < 2; i++ {
		s, err := c.LogsAt(context.Background(), "p", "api", "a.go", 4, "payment failed")
		if err != nil || s.Count != 1 {
			t.Fatalf("site %+v err %v", s, err)
		}
	}
	if len(bodies) != 2 || !strings.Contains(bodies[0], "code.lineno") || strings.Contains(bodies[1], "code.lineno") {
		t.Fatalf("want location query then text query, once (cached): %v", bodies)
	}
}
