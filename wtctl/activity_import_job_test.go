package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

func TestNdjsonGzipOneEventPerLine(t *testing.T) {
	b, err := ndjsonGzip([]map[string]any{{"a": 1}, {"b": 2}})
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	if string(raw) != "{\"a\":1}\n{\"b\":2}\n" {
		t.Fatalf("body %q", raw)
	}
}

func TestPrintImportJobReportsFailure(t *testing.T) {
	var out bytes.Buffer
	ok := `{"job_id":"j1","status":"done","accepted":3,"rejected_count":1,"rejected":[{"line":2,"problem":{"detail":"bad"}}]}`
	if err := printImportJob([]byte(ok), 0, &out); err != nil || !strings.Contains(out.String(), "3 accepted, 1 rejected") {
		t.Fatalf("%v %q", err, out.String())
	}
	if err := printImportJob([]byte(`{"job_id":"j2","status":"failed","error":"quota"}`), 0, &out); err == nil {
		t.Fatal("a failed job is an error")
	}
}
