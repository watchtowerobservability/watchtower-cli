package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

type fakeKafka struct {
	acls   map[string]ACL
	quotas map[string]Quota
}

func newFakeKafka() *fakeKafka {
	return &fakeKafka{acls: map[string]ACL{}, quotas: map[string]Quota{}}
}

func (f *fakeKafka) ACLs(context.Context) ([]ACL, error) {
	var out []ACL
	for _, a := range f.acls {
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeKafka) CreateACLs(_ context.Context, as []ACL) error {
	for _, a := range as {
		f.acls[a.key()] = a
	}
	return nil
}

func (f *fakeKafka) Quotas(context.Context) ([]Quota, error) {
	var out []Quota
	for _, q := range f.quotas {
		out = append(out, q)
	}
	return out, nil
}

func (f *fakeKafka) SetQuotas(_ context.Context, qs []Quota) error {
	for _, q := range qs {
		f.quotas[q.User] = q
	}
	return nil
}

var testPrincipals = []Principal{
	{User: "wt-gateway", Role: "gateway", ProducerByteRate: 50 << 20, RequestPercentage: 30},
	{User: "wt-worker", Role: "worker", ConsumerByteRate: 100 << 20, RequestPercentage: 50},
	{User: "wt-edge", Role: "edge", ProducerByteRate: 5 << 20},
}

func has(acls []ACL, user, typ, op, name string) bool {
	for _, a := range acls {
		if a.Principal == "User:"+user && a.Type == typ && a.Op == op && (a.Name == name ||
			(a.Pattern == "prefixed" && strings.HasPrefix(name, a.Name))) {
			return true
		}
	}
	return false
}

func TestPlanIsIdempotent(t *testing.T) {
	acls, quotas, err := Render(testPrincipals, "")
	if err != nil {
		t.Fatal(err)
	}
	fk := newFakeKafka()
	ctx := context.Background()
	pl, err := Diff(ctx, fk, acls, quotas)
	if err != nil || len(pl.AddACLs) == 0 || len(pl.SetQuotas) != 3 {
		t.Fatalf("first plan %+v err %v", pl, err)
	}
	if err := fk.CreateACLs(ctx, pl.AddACLs); err != nil {
		t.Fatal(err)
	}
	if err := fk.SetQuotas(ctx, pl.SetQuotas); err != nil {
		t.Fatal(err)
	}
	pl, err = Diff(ctx, fk, acls, quotas)
	if err != nil || len(pl.AddACLs)+len(pl.SetQuotas) != 0 {
		t.Fatalf("second plan not empty: %+v err %v", pl, err)
	}
	var b bytes.Buffer
	pl.print(&b)
	if !strings.Contains(b.String(), "no changes") {
		t.Fatalf("print: %q", b.String())
	}
}

func TestWorkerCannotWriteOtlpTopics(t *testing.T) {
	acls, _, _ := Render(testPrincipals, "")
	for _, s := range otlpSignals {
		if has(acls, "wt-worker", "topic", "Write", "wt.otlp."+s) {
			t.Fatalf("worker can write wt.otlp.%s", s)
		}
		if !has(acls, "wt-worker", "topic", "Read", "wt.otlp."+s) {
			t.Fatalf("worker cannot read wt.otlp.%s", s)
		}
		if !has(acls, "wt-worker", "topic", "Write", "wt.otlp."+s+".slow") {
			t.Fatalf("worker cannot write the %s slow lane", s)
		}
	}
	if !has(acls, "wt-worker", "topic", "Write", "wt.dlq.logs") {
		t.Fatal("worker cannot write the DLQ")
	}
}

func TestGatewayCannotReadOtlpTopics(t *testing.T) {
	acls, _, _ := Render(testPrincipals, "")
	if has(acls, "wt-gateway", "topic", "Read", "wt.otlp.logs") {
		t.Fatal("gateway can read wt.otlp.logs")
	}
	if !has(acls, "wt-gateway", "topic", "Write", "wt.otlp.logs") {
		t.Fatal("gateway cannot write wt.otlp.logs")
	}
	if has(acls, "wt-edge", "topic", "Write", "wt.otlp.logs") || !has(acls, "wt-edge", "topic", "Write", "wt.errors") {
		t.Fatal("edge ACLs wrong")
	}
}

func TestQuotaPerPrincipal(t *testing.T) {
	_, quotas, _ := Render(testPrincipals, "")
	got := map[string]Quota{}
	for _, q := range quotas {
		got[q.User] = q
	}
	if got["wt-gateway"].ProducerByteRate != 50<<20 || got["wt-worker"].ConsumerByteRate != 100<<20 ||
		got["wt-edge"].ProducerByteRate != 5<<20 || got["wt-edge"].RequestPercentage != 0 {
		t.Fatalf("quotas %+v", got)
	}
	if _, _, err := Render([]Principal{{User: "x", Role: "nope"}}, ""); err == nil {
		t.Fatal("unknown role accepted")
	}
}
