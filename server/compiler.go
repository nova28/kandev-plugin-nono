package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var excludedGroups = []string{"system_read_macos", "system_read_linux_core", "system_write_macos", "system_write_linux", "user_tools", "homebrew_macos", "homebrew_linux", "dangerous_commands", "dangerous_commands_macos", "dangerous_commands_linux"}

var forbiddenArguments = []string{"--allow-net", "--sandbox-policy", "--profile", "--allow", "--read", "--write", "--detached", "--no-sandbox", "--no-supervisor", "--allow-domain", "--open-port", "--connect-port", "--allow-command", "--bypass-protection"}
var forbiddenEnvironmentKeys = []string{"NONO_ALLOW_NET", "NONO_PROFILE", "NONO_SANDBOX_POLICY"}

func (*nonoPlugin) CompileSandboxPolicy(ctx context.Context, req *pluginsdk.CompileSandboxPolicyRequest) (*pluginsdk.CompileSandboxPolicyResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	selected, ok := hostFor(req.Runtime)
	if !ok || !supportedHost(req.Runtime) || req.Runtime.RuntimeVersion != runtimeVersion || req.Runtime.RuntimeDigest != selected.digest {
		return nil, status.Error(codes.FailedPrecondition, "unsupported sandbox runtime")
	}
	if req.Policy == nil || req.Policy.Grants == nil || len(req.Policy.Grants.Filesystem) > 256 || len(req.Policy.Grants.Network) > 256 {
		return nil, status.Error(codes.InvalidArgument, "invalid sandbox policy")
	}
	if selected.os == "darwin" {
		return compileDarwin(req, reply)
	}
	filesystem, err := compileFilesystem(req.Policy.Grants.Filesystem)
	if err != nil {
		return nil, err
	}
	network, err := compileNetwork(req.Policy.Grants, req.Endpoints)
	if err != nil {
		return nil, err
	}
	keys, err := childEnvironmentKeys(req.Policy.Grants.EnvironmentKeys)
	if err != nil {
		return nil, err
	}
	childVars, childBindings, err := compileChildDirectories(req, false)
	if err != nil {
		return nil, err
	}
	profile := map[string]any{
		"meta":        map[string]any{"name": "kandev-managed", "version": "1.0.0"},
		"groups":      map[string]any{"exclude": excludedGroups},
		"filesystem":  filesystem,
		"network":     network,
		"workdir":     map[string]any{"access": "none"},
		"environment": map[string]any{"allow_vars": keys, "set_vars": childVars},
		"security": map[string]any{"capability_elevation": true, "signal_mode": "isolated", "process_info_mode": "isolated", "wsl2_proxy_policy": "error",
			"approval_backends": map[string]any{"kandev": map[string]any{"type": "webhook", "url": "", "timeout_secs": 60}},
			"approval_defaults": map[string]any{"backend": "kandev"}},
	}
	if childVars == nil {
		delete(profile["environment"].(map[string]any), "set_vars")
	}
	content, err := json.Marshal(profile)
	if err != nil {
		return nil, status.Error(codes.Internal, "sandbox compilation failed")
	}
	result := &pluginsdk.CompileSandboxPolicyResponse{Context: reply, Compiled: &pluginsdk.SandboxCompiledPolicy{
		Prefix: []*pluginsdk.SandboxArgument{
			{Value: &pluginsdk.SandboxArgument_RuntimeReference{RuntimeReference: pluginsdk.SandboxRuntimeReferenceKey}},
			literal("run"), literal("--silent"), literal("--profile"),
			{Value: &pluginsdk.SandboxArgument_ArtifactReference{ArtifactReference: "profile.json"}}, literal("--"),
		},
		Artifacts:            []*pluginsdk.SandboxArtifact{{Name: "profile.json", Kind: pluginsdk.SandboxArtifactProfile, ContentUtf8: string(content), Bindings: []*pluginsdk.SandboxArtifactBinding{{Path: []string{"security", "approval_backends", "kandev", "url"}, RuntimeReference: approvalEndpoint}}}},
		EffectiveGrants:      proto.Clone(req.Policy.Grants).(*pluginsdk.SandboxGrants),
		Constraints:          &pluginsdk.SandboxOverrideConstraints{ForbiddenArguments: forbiddenArguments, ForbiddenEnvironmentKeys: forbiddenEnvironmentKeys},
		RequiredCapabilities: []string{"private_artifacts", "foreground_process", "approval_webhook", "isolated_environment"},
	}}
	result.Compiled.Artifacts[0].Bindings = append(result.Compiled.Artifacts[0].Bindings, childBindings...)
	if len(req.Policy.Grants.Network) > 0 || req.Policy.Grants.KandevMcp {
		result.Compiled.RequiredCapabilities = append(result.Compiled.RequiredCapabilities, "egress_proxy")
		result.Compiled.Artifacts[0].Bindings = append(result.Compiled.Artifacts[0].Bindings, &pluginsdk.SandboxArtifactBinding{Path: []string{"network", "upstream_proxy"}, RuntimeReference: "sandbox.egress.endpoint"})
	}
	return result, nil
}

func compileFilesystem(grants []*pluginsdk.SandboxFilesystemGrant) (map[string][]string, error) {
	result := map[string][]string{"allow": {}, "read": {}}
	for _, grant := range grants {
		if grant == nil || !filepath.IsAbs(grant.Path) || filepath.Clean(grant.Path) != grant.Path || strings.ContainsAny(grant.Path, "$~") || strings.ContainsFunc(grant.Path, unicode.IsControl) {
			return nil, status.Error(codes.InvalidArgument, "unsupported sandbox path")
		}
		key := "read"
		if grant.Writable {
			key = "allow"
		}
		result[key] = append(result[key], grant.Path)
	}
	return result, nil
}

func literal(value string) *pluginsdk.SandboxArgument {
	return &pluginsdk.SandboxArgument{Value: &pluginsdk.SandboxArgument_Literal{Literal: value}}
}
