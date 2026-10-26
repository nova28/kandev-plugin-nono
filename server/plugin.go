package main

import (
	"context"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	providerVersion = "0.1.0"
	runtimeVersion  = "0.80.0"
	runtimeDigest   = "a66396777ed756dff196ef61cf704abd4feebf58599d41e2da3363bbe90e22af"
	// runtimeDigestDarwin pins the packaged darwin/arm64 executable of the same release.
	runtimeDigestDarwin = "e95479a2ef64b19e3245a90a60024bb248e96e8ec234ffeb25e062ddd45b1417"
	approvalEndpoint    = "sandbox.approval.endpoint"
)

type nonoPlugin struct{ pluginsdk.UnimplementedPlugin }

func replyContext(ctx context.Context, req *pluginsdk.SandboxRequestContext) (*pluginsdk.SandboxResponseContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil || req.ProtocolMajor != 1 || req.ProviderKey != "nono" || req.InstallationId == "" || req.OperationId == "" || req.AttemptId == "" || req.Generation == 0 || req.DeadlineUnixMs <= time.Now().UnixMilli() {
		return nil, status.Error(codes.InvalidArgument, "invalid sandbox operation")
	}
	return &pluginsdk.SandboxResponseContext{SchemaVersion: 1, OperationId: req.OperationId}, nil
}

// host names one supported OS and architecture pair and the packaged runtime for it.
type host struct{ os, architecture, artifact, digest string }

var hosts = []host{
	{"linux", "amd64", "runtime/nono-linux-amd64", runtimeDigest},
	{"darwin", "arm64", "runtime/nono-darwin-arm64", runtimeDigestDarwin},
}

func hostFor(runtime *pluginsdk.SandboxRuntimeFacts) (host, bool) {
	if runtime == nil {
		return host{}, false
	}
	for _, candidate := range hosts {
		if candidate.os == runtime.Os && candidate.architecture == runtime.Architecture {
			return candidate, true
		}
	}
	return host{}, false
}

func supportedHost(runtime *pluginsdk.SandboxRuntimeFacts) bool {
	_, ok := hostFor(runtime)
	return ok && (runtime.Transport == "local" || runtime.Transport == "worktree")
}

func (*nonoPlugin) DescribeSandboxProvider(ctx context.Context, req *pluginsdk.DescribeSandboxProviderRequest) (*pluginsdk.DescribeSandboxProviderResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	selected, ok := hostFor(req.Runtime)
	if !ok {
		return nil, pluginsdk.ErrSandboxHostUnsupported()
	}
	if !supportedHost(req.Runtime) {
		return nil, status.Error(codes.FailedPrecondition, "unsupported sandbox host")
	}
	if selected.os == "darwin" {
		return &pluginsdk.DescribeSandboxProviderResponse{Context: reply, Description: describeDarwin(selected)}, nil
	}
	return &pluginsdk.DescribeSandboxProviderResponse{Context: reply, Description: &pluginsdk.SandboxProviderDescription{
		DisplayName: "Nono", ProviderVersion: providerVersion, RuntimeVersion: runtimeVersion,
		RuntimeSources: []*pluginsdk.SandboxRuntimeSource{
			{Key: "nono.session-registry.v1", Kind: "identity", RelativeDirectory: "nono/sessions", FilenameSuffix: ".json", MaxDepth: 1, MaxFiles: 16, MaxBytes: 64 << 10},
			{Key: "nono.audit.v1", Kind: "audit", RelativeDirectory: "nono/audit", FilenameSuffix: "audit-events.ndjson", MaxDepth: 2, MaxFiles: 16, MaxBytes: 1 << 20},
		},
		ApprovalWire:        &pluginsdk.SandboxApprovalWire{ContentType: "application/json", AllowOnceBodyUtf8: `{"decision":"granted"}`, DenyBodyUtf8: `{"decision":"denied"}`, TimeoutBodyUtf8: `{"decision":"timeout"}`},
		RuntimeArtifact:     &pluginsdk.SandboxRuntimeArtifact{RelativePath: selected.artifact, Sha256: selected.digest},
		SupportedTransports: []string{"local", "worktree"},
		SupportedFeatures:   []string{"filesystem", "network_proxy", "approval_webhook"},
		ReportClasses:       []string{"filesystem"},
		Limitations:         []string{"Linux amd64 only. Kernel enforcement is verified at launch.", "Network grants authorize destination TCP connections through the proxy.", "Audit reports cover filesystem capability decisions only. Other denials are not recorded."},
	}}, nil
}
