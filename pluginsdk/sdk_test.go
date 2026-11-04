package pluginsdk

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type fake struct{}

func (fake) Describe() Manifest {
	return Manifest{Name: "fake", Version: "1", Kinds: []string{KindSource}}
}
func (fake) Query(_ context.Context, r QueryRequest) (Frames, error) {
	return Frames{Frames: []Frame{{Name: r.Query, Kind: FrameTable, Fields: []Field{{Name: "n", Values: []any{1.0}}}}}}, nil
}
func (fake) Process(_ context.Context, p Payload) (Payload, error) {
	p.Body["seen"] = true
	return p, nil
}

func dial(t *testing.T, impl any) *Remote {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	s := grpc.NewServer()
	Register(s, impl)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return NewRemote(cc)
}

func TestSourceQueryRoundtripOverGrpc(t *testing.T) {
	r := dial(t, fake{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := r.Describe(ctx)
	if err != nil || m.Name != "fake" {
		t.Fatalf("describe: %v %+v", err, m)
	}
	f, err := r.Query(ctx, QueryRequest{Query: "q1", From: time.Unix(0, 0).UTC(), Step: time.Minute})
	if err != nil || len(f.Frames) != 1 || f.Frames[0].Name != "q1" {
		t.Fatalf("query: %v %+v", err, f)
	}
	// fake is not an Action.
	if _, err := r.Run(ctx, RunRequest{}); err == nil {
		t.Fatal("Run on a source-only plugin must fail")
	}
}

func TestFilterOnlyAppliedToNotificationPayloads(t *testing.T) {
	r := dial(t, fake{})
	ctx := context.Background()
	if _, err := r.Process(ctx, Payload{Kind: "ingest", Body: map[string]any{}}); err == nil {
		t.Fatal("ingest payloads must be refused client-side")
	}
	// The server refuses too (a client that skips the check).
	if _, err := invoke[Payload, Payload](ctx, r.cc, "Process", Payload{Kind: "ingest", Body: map[string]any{}}); err == nil {
		t.Fatal("ingest payloads must be refused server-side")
	}
	p, err := r.Process(ctx, Payload{Kind: PayloadNotification, Body: map[string]any{}})
	if err != nil || p.Body["seen"] != true {
		t.Fatalf("notification: %v %+v", err, p)
	}
}

func TestManifestValidation(t *testing.T) {
	m, err := ParseManifest([]byte("name: hello\nversion: 1.0.0\nkinds: [source]\npermissions:\n  egress_hosts: [api.example.com]\n"))
	if err != nil || m.Permissions.MaxMemMB != DefaultMemMB {
		t.Fatalf("%v %+v", err, m)
	}
	for _, bad := range []string{"name: Bad Name\nversion: 1\nkinds: [source]", "name: x\nversion: 1\nkinds: [ingest]", "name: x\nversion: 1"} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
