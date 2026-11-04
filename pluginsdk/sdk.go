// Package pluginsdk is the Watchtower plugin SDK (ADR-0036): a plugin is a separate process
// served over HashiCorp go-plugin (gRPC, MPL-2.0) that implements Source, Action and/or Filter.
//
// Wire format: each RPC carries a google.protobuf.BytesValue holding the JSON of the request or
// response type (see proto/plugin.proto), so the SDK needs no generated code.
package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ServiceName is the gRPC service every plugin registers.
const ServiceName = "watchtower.plugin.v1.Plugin"

// PluginKey is the go-plugin set key.
const PluginKey = "plugin"

// Handshake is shared by the SDK and the runner; the cookie only stops accidental execution.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "WT_PLUGIN",
	MagicCookieValue: "watchtower-plugin-v1",
}

// Serve runs the plugin; impl may implement any of Source, Action and Filter. It blocks.
func Serve(impl any) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         plugin.PluginSet{PluginKey: &grpcPlugin{impl: impl}},
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}

// ClientPlugins is the plugin set for a go-plugin client (the runner).
func ClientPlugins() plugin.PluginSet { return plugin.PluginSet{PluginKey: &grpcPlugin{}} }

type grpcPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl any
}

func (p *grpcPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	Register(s, p.impl)
	return nil
}

func (p *grpcPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, cc *grpc.ClientConn) (any, error) {
	return NewRemote(cc), nil
}

// Register adds the plugin service for impl to a gRPC server.
func Register(s grpc.ServiceRegistrar, impl any) {
	s.RegisterService(&serviceDesc, &server{impl: impl})
}

type server struct{ impl any }

type describer interface{ Describe() Manifest }

func unimplemented(kind string) error {
	return status.Error(codes.Unimplemented, "plugin does not implement "+kind)
}

func (s *server) describe(_ context.Context, _ struct{}) (Manifest, error) {
	d, ok := s.impl.(describer)
	if !ok {
		return Manifest{}, unimplemented("Describe")
	}
	return d.Describe(), nil
}

func (s *server) query(ctx context.Context, r QueryRequest) (Frames, error) {
	src, ok := s.impl.(Source)
	if !ok {
		return Frames{}, unimplemented(KindSource)
	}
	return src.Query(ctx, r)
}

func (s *server) run(ctx context.Context, r RunRequest) (Outputs, error) {
	a, ok := s.impl.(Action)
	if !ok {
		return nil, unimplemented(KindAction)
	}
	return a.Run(ctx, r)
}

func (s *server) process(ctx context.Context, p Payload) (Payload, error) {
	f, ok := s.impl.(Filter)
	if !ok {
		return Payload{}, unimplemented(KindFilter)
	}
	if !AllowedPayload(p.Kind) {
		return Payload{}, status.Error(codes.InvalidArgument, "filters only apply to notification and workflow payloads")
	}
	return f.Process(ctx, p)
}

type unary = func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error)

func handler[Req, Resp any](call func(*server, context.Context, Req) (Resp, error)) unary {
	return func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var in wrapperspb.BytesValue
		if err := dec(&in); err != nil {
			return nil, err
		}
		var req Req
		if len(in.Value) > 0 {
			if err := json.Unmarshal(in.Value, &req); err != nil {
				return nil, status.Error(codes.InvalidArgument, "bad request")
			}
		}
		resp, err := call(srv.(*server), ctx, req)
		if err != nil {
			if _, ok := status.FromError(err); ok {
				return nil, err
			}
			return nil, status.Error(codes.Unknown, err.Error())
		}
		b, err := json.Marshal(resp)
		if err != nil {
			return nil, status.Error(codes.Internal, "unencodable response")
		}
		return wrapperspb.Bytes(b), nil
	}
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Describe", Handler: handler((*server).describe)},
		{MethodName: "Query", Handler: handler((*server).query)},
		{MethodName: "Run", Handler: handler((*server).run)},
		{MethodName: "Process", Handler: handler((*server).process)},
	},
	Metadata: "plugin.proto",
}

// Remote is the client side of the service (used by the runner).
type Remote struct{ cc grpc.ClientConnInterface }

// NewRemote wraps a connection to a plugin.
func NewRemote(cc grpc.ClientConnInterface) *Remote { return &Remote{cc: cc} }

func invoke[Req, Resp any](ctx context.Context, cc grpc.ClientConnInterface, method string, req Req) (Resp, error) {
	var resp Resp
	b, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	var out wrapperspb.BytesValue
	if err := cc.Invoke(ctx, "/"+ServiceName+"/"+method, wrapperspb.Bytes(b), &out); err != nil {
		return resp, err
	}
	if len(out.Value) == 0 {
		return resp, errors.New("empty plugin response")
	}
	return resp, json.Unmarshal(out.Value, &resp)
}

// Describe returns the plugin's manifest.
func (r *Remote) Describe(ctx context.Context) (Manifest, error) {
	return invoke[struct{}, Manifest](ctx, r.cc, "Describe", struct{}{})
}

// Query runs a Source query.
func (r *Remote) Query(ctx context.Context, q QueryRequest) (Frames, error) {
	return invoke[QueryRequest, Frames](ctx, r.cc, "Query", q)
}

// Run runs an Action.
func (r *Remote) Run(ctx context.Context, q RunRequest) (Outputs, error) {
	return invoke[RunRequest, Outputs](ctx, r.cc, "Run", q)
}

// Process runs a Filter; payload kinds other than notification and workflow are refused here
// before they cross the process boundary.
func (r *Remote) Process(ctx context.Context, p Payload) (Payload, error) {
	if !AllowedPayload(p.Kind) {
		return Payload{}, errors.New("filters only apply to notification and workflow payloads")
	}
	return invoke[Payload, Payload](ctx, r.cc, "Process", p)
}
