package ascode

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A settings singleton is read flat, compared on the declared fields only, and updated with the kind's method.
func TestIssueSettingsSingletonPatchesAndExportsWithoutNulls(t *testing.T) {
	live := map[string]any{"store_ip": false, "safe_fields": []any{"a"}, "auto_resolve_days": nil}
	var method string
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method = r.Method
			_ = json.NewDecoder(r.Body).Decode(&sent)
		}
		_ = json.NewEncoder(w).Encode(live)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "k", "prj_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	k := ByKind("IssueSettings")
	it, err := c.Get(context.Background(), k, "")
	if err != nil {
		t.Fatal(err)
	}
	if d := ExportDoc(k, "", it.Body); len(d.Spec) != 2 || d.Spec["store_ip"] != false {
		t.Fatalf("export keeps nulls: %v", d.Spec)
	}
	if _, err := c.Update(context.Background(), k, it, "", map[string]any{"store_ip": true}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPatch || sent["store_ip"] != true {
		t.Fatalf("update sent %s %v", method, sent)
	}
	if me, _ := route(k, OpUpdate); me != http.MethodPatch {
		t.Fatalf("schema check would use %s", me)
	}
}
