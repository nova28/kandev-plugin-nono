package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// darwinExcludedGroups removes every default group that grants the shared
// temporary directories (system_write_macos), user caches, tools, Homebrew,
// and the command deny lists. The read-only system_read_macos group stays: an
// executable cannot start under Seatbelt without it. The credential, keychain,
// browser and private-data deny groups are required by Nono and stay.
var darwinExcludedGroups = []string{"system_write_macos", "user_caches_macos", "user_tools", "homebrew_macos", "go_runtime_macos", "dangerous_commands", "dangerous_commands_macos"}

// darwinDeviceGrants are the device nodes a child needs once system_write_macos
// (which grants all of /dev) is excluded.
var darwinDeviceGrants = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/dtracehelper"}

// deniedTemporaryRoots are the shared temporary roots a darwin child never receives.
var deniedTemporaryRoots = []string{"/tmp", "/private/tmp", "/var/folders", "/private/var/folders"}

func describeDarwin(selected host) *pluginsdk.SandboxProviderDescription {
	return &pluginsdk.SandboxProviderDescription{
		DisplayName: "Nono", ProviderVersion: providerVersion, RuntimeVersion: runtimeVersion,
		RuntimeArtifact:     &pluginsdk.SandboxRuntimeArtifact{RelativePath: selected.artifact, Sha256: selected.digest},
		SupportedTransports: []string{"local", "worktree"},
		SupportedFeatures:   []string{"filesystem", "network_proxy"},
		Limitations: []string{
			"macOS Apple Silicon only. Confinement is Seatbelt and is verified when the agent runtime starts.",
			"Approvals are not supported on macOS.",
			"Filesystem denials are not reported on macOS.",
			"A process that leaves the process group cannot be tracked.",
			"Network grants authorize destination TCP connections through the proxy.",
		},
	}
}

// darwinTemporaryDirectory validates the per-attempt temporary directory and
// reports whether the request carries the complete child directory set.
func darwinTemporaryDirectory(req *pluginsdk.CompileSandboxPolicyRequest) (string, error) {
	for _, ref := range req.References {
		if ref == nil || ref.Key != "sandbox.child.tmp" {
			continue
		}
		tmp := ref.Value
		if !filepath.IsAbs(tmp) || filepath.Clean(tmp) != tmp || strings.ContainsAny(tmp, "$~\x00\r\n") {
			return "", status.Error(codes.InvalidArgument, "invalid child directory reference")
		}
		for _, root := range deniedTemporaryRoots {
			if tmp == root || strings.HasPrefix(tmp, root+string(filepath.Separator)) {
				return "", status.Error(codes.InvalidArgument, "child temporary directory is a shared temporary root")
			}
		}
		return tmp, nil
	}
	return "", status.Error(codes.InvalidArgument, "child temporary directory is required")
}

// compileDarwinFilesystem returns the sorted, deduplicated allow and read lists.
// The attempt's temporary directory is writable and nothing else outside the
// neutral grants and the device nodes is.
func compileDarwinFilesystem(grants []*pluginsdk.SandboxFilesystemGrant, tmp string) (map[string][]string, error) {
	result, err := compileFilesystem(grants)
	if err != nil {
		return nil, err
	}
	result["allow"] = append(result["allow"], tmp)
	for _, device := range darwinDeviceGrants {
		result["allow"] = append(result["allow"], device)
	}
	for key, paths := range result {
		slices.Sort(paths)
		result[key] = slices.Compact(paths)
	}
	return result, nil
}

// compileDarwinChildDirectories binds the child environment. The temporary
// directory is always bound; HOME, XDG_CONFIG_HOME and XDG_STATE_HOME are bound
// only with an agent_state grant, as on Linux.
func compileDarwinChildDirectories(req *pluginsdk.CompileSandboxPolicyRequest) (map[string]string, []*pluginsdk.SandboxArtifactBinding, error) {
	if len(req.References) == len(childDirectories) {
		return compileChildDirectories(req, true)
	}
	if len(req.References) != 1 {
		return nil, nil, status.Error(codes.InvalidArgument, "invalid child directory reference")
	}
	return map[string]string{"TMPDIR": ""}, []*pluginsdk.SandboxArtifactBinding{{Path: []string{"environment", "set_vars", "TMPDIR"}, RuntimeReference: "sandbox.child.tmp"}}, nil
}

func compileDarwin(req *pluginsdk.CompileSandboxPolicyRequest, reply *pluginsdk.SandboxResponseContext) (*pluginsdk.CompileSandboxPolicyResponse, error) {
	tmp, err := darwinTemporaryDirectory(req)
	if err != nil {
		return nil, err
	}
	filesystem, err := compileDarwinFilesystem(req.Policy.Grants.Filesystem, tmp)
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
	childVars, bindings, err := compileDarwinChildDirectories(req)
	if err != nil {
		return nil, err
	}
	profile := map[string]any{
		"meta":        map[string]any{"name": "kandev-managed", "version": "1.0.0"},
		"groups":      map[string]any{"exclude": darwinExcludedGroups},
		"filesystem":  filesystem,
		"network":     network,
		"workdir":     map[string]any{"access": "none"},
		"environment": map[string]any{"allow_vars": keys, "set_vars": childVars},
		"security":    map[string]any{"capability_elevation": false, "signal_mode": "isolated", "process_info_mode": "isolated"},
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
		Artifacts:            []*pluginsdk.SandboxArtifact{{Name: "profile.json", Kind: pluginsdk.SandboxArtifactProfile, ContentUtf8: string(content), Bindings: bindings}},
		EffectiveGrants:      proto.Clone(req.Policy.Grants).(*pluginsdk.SandboxGrants),
		Constraints:          &pluginsdk.SandboxOverrideConstraints{ForbiddenArguments: forbiddenArguments, ForbiddenEnvironmentKeys: forbiddenEnvironmentKeys},
		RequiredCapabilities: []string{"private_artifacts", "foreground_process", "isolated_environment"},
	}}
	if len(req.Policy.Grants.Network) > 0 || req.Policy.Grants.KandevMcp {
		result.Compiled.RequiredCapabilities = append(result.Compiled.RequiredCapabilities, "egress_proxy")
		result.Compiled.Artifacts[0].Bindings = append(result.Compiled.Artifacts[0].Bindings, &pluginsdk.SandboxArtifactBinding{Path: []string{"network", "upstream_proxy"}, RuntimeReference: "sandbox.egress.endpoint"})
	}
	return result, nil
}
