package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func thinMachO(tag byte) []byte {
	return append([]byte{0xcf, 0xfa, 0xed, 0xfe}, tag, tag, tag, tag)
}

// fatOf builds a 32-bit universal header around the slices (cpu types: x86_64, arm64).
func fatOf(slices ...[]byte) []byte {
	cpus := []uint32{0x01000007, 0x0100000c}
	out := binary.BigEndian.AppendUint32(nil, fatMagic)
	out = binary.BigEndian.AppendUint32(out, uint32(len(slices)))
	off := 8 + 20*len(slices)
	for i, s := range slices {
		out = binary.BigEndian.AppendUint32(out, cpus[i])
		out = binary.BigEndian.AppendUint32(out, 0)
		out = binary.BigEndian.AppendUint32(out, uint32(off))
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		out = binary.BigEndian.AppendUint32(out, 0)
		off += len(s)
	}
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

func TestSplitFatMachO(t *testing.T) {
	a, b := thinMachO(1), thinMachO(2)
	got, ok := splitFatMachO(fatOf(a, b))
	if !ok || len(got) != 2 || got[0].arch != "x86_64" || got[1].arch != "arm64" {
		t.Fatalf("split = %v %v", got, ok)
	}
	if string(got[0].data) != string(a) || string(got[1].data) != string(b) {
		t.Fatal("slice bytes differ")
	}
	if _, ok := splitFatMachO(fatOf(a, b)[:30]); ok {
		t.Fatal("truncated file must be refused")
	}
	// a Java class file shares the magic: cafebabe, minor 0, major 52
	if _, ok := splitFatMachO([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 1, 2, 3}); ok {
		t.Fatal("class file is not a fat Mach-O")
	}
	if debugKind(fatOf(a, b)[:32]) != "macho" {
		t.Fatal("fat header must be kind macho")
	}
}

func TestDebugFilesUploadSplitsFatMachO(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "App"), fatOf(thinMachO(1), thinMachO(2)))
	srv, got := artifactServer(t, http.StatusCreated)
	o := artifactOpts{api: srv.URL, key: "k", project: "prj_1"}
	if err := debugFilesUpload(context.Background(), o, []string{dir}, io.Discard); err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, u := range got() {
		names[u.name] = u.kind
	}
	if len(names) != 2 || names["App.x86_64"] != "macho" || names["App.arm64"] != "macho" {
		t.Fatalf("uploads = %v", names)
	}
}

func TestUploadsReuseOneConnection(t *testing.T) {
	var mu sync.Mutex
	conns := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			mu.Lock()
			conns++
			mu.Unlock()
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	o := artifactOpts{api: srv.URL, key: "k", project: "prj_1"}
	for i := 0; i < 4; i++ {
		if err := uploadArtifact(context.Background(), o, "sourcemap", fmt.Sprintf("%d.map", i), []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if conns != 1 {
		t.Fatalf("%d connections for 4 uploads, want 1", conns)
	}
}

func TestLargeFilesUsePresignedLinkAndFallBack(t *testing.T) {
	old := presignOver
	presignOver = 4
	t.Cleanup(func() { presignOver = old })
	var mu sync.Mutex
	var seq []string
	linkStatus := http.StatusOK
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seq = append(seq, r.Method+" "+r.URL.Path)
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/upload-url"):
			if linkStatus != http.StatusOK {
				w.WriteHeader(linkStatus)
				return
			}
			_, _ = fmt.Fprintf(w, `{"upload_id":"u1","url":%q}`, srv.URL+"/blob")
		case r.URL.Path == "/blob":
			if r.Method != http.MethodPut || string(body) != "0123456789" {
				t.Errorf("blob PUT = %s %q", r.Method, body)
			}
		case strings.HasSuffix(r.URL.Path, "/complete"):
			if r.URL.Query().Get("upload_id") != "u1" || r.URL.Query().Get("name") != "big.so" {
				t.Errorf("complete query = %v", r.URL.Query())
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	t.Cleanup(srv.Close)
	o := artifactOpts{api: srv.URL, key: "k", project: "prj_1"}
	if err := uploadArtifact(context.Background(), o, "elf", "big.so", []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	want := "POST /v1/projects/prj_1/artifacts/upload-url,PUT /blob,POST /v1/projects/prj_1/artifacts/complete"
	if strings.Join(seq, ",") != want {
		t.Fatalf("sequence = %v", seq)
	}
	// no link offered (503): the file goes through the API as before
	seq, linkStatus = nil, http.StatusServiceUnavailable
	if err := uploadArtifact(context.Background(), o, "elf", "big.so", []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seq, ",") != "POST /v1/projects/prj_1/artifacts/upload-url,POST /v1/projects/prj_1/artifacts" {
		t.Fatalf("fallback sequence = %v", seq)
	}
}
