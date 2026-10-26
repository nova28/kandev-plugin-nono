package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// attemptTmp stands in for the per-attempt directory core reserves under its private state root.
const attemptTmp = "/Users/fixture/.kandev/attempt-1/tmp"

func darwinFacts() *pluginsdk.SandboxRuntimeFacts {
	return &pluginsdk.SandboxRuntimeFacts{Os: "darwin", Architecture: "arm64", Transport: "local", RuntimeVersion: "0.80.0", RuntimeDigest: runtimeDigestDarwin}
}

func darwinRequest(t *testing.T) *pluginsdk.CompileSandboxPolicyRequest {
	t.Helper()
	req := compileRequest(t)
	req.Runtime = darwinFacts()
	req.References = []*pluginsdk.SandboxRuntimeReference{{Key: "sandbox.child.tmp", Value: attemptTmp}}
	return req
}

type darwinProfile struct {
	Groups     struct{ Exclude []string }
	Filesystem struct{ Allow, Read []string }
	Network    struct {
		Block bool
	}
	Environment struct {
		SetVars map[string]string `json:"set_vars"`
	}
	Security map[string]any
}

func compileDarwinProfile(t *testing.T, req *pluginsdk.CompileSandboxPolicyRequest) (*pluginsdk.CompileSandboxPolicyResponse, darwinProfile) {
	t.Helper()
	response, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.NoError(t, err)
	var profile darwinProfile
	require.NoError(t, json.Unmarshal([]byte(response.Compiled.Artifacts[0].ContentUtf8), &profile))
	return response, profile
}

func TestDescribeDarwinDeclaresNoApprovalReportOrStatusEvidence(t *testing.T) {
	req := darwinRequest(t)
	result, err := (&nonoPlugin{}).DescribeSandboxProvider(context.Background(), &pluginsdk.DescribeSandboxProviderRequest{Context: req.Context, Runtime: req.Runtime})
	require.NoError(t, err)
	description := result.Description
	require.Equal(t, "runtime/nono-darwin-arm64", description.RuntimeArtifact.RelativePath)
	require.Equal(t, runtimeDigestDarwin, description.RuntimeArtifact.Sha256)
	require.Nil(t, description.ApprovalWire)
	require.Empty(t, description.RuntimeSources, "no status evidence is declared, so status stays unknown")
	require.Empty(t, description.ReportClasses)
	require.NotContains(t, description.SupportedFeatures, "approval_webhook")
	require.Equal(t, []string{"local", "worktree"}, description.SupportedTransports)
}

func TestDescribeRefusesEveryOtherHostWithTheTypedRefusal(t *testing.T) {
	for _, facts := range []*pluginsdk.SandboxRuntimeFacts{
		{Os: "darwin", Architecture: "amd64", Transport: "local"},
		{Os: "linux", Architecture: "arm64", Transport: "local"},
		{Os: "windows", Architecture: "amd64", Transport: "local"},
		nil,
	} {
		_, err := (&nonoPlugin{}).DescribeSandboxProvider(context.Background(), &pluginsdk.DescribeSandboxProviderRequest{Context: requestContext(), Runtime: facts})
		require.True(t, pluginsdk.IsSandboxHostUnsupported(err), "%v", facts)
	}
	_, err := (&nonoPlugin{}).DescribeSandboxProvider(context.Background(), &pluginsdk.DescribeSandboxProviderRequest{Context: requestContext(), Runtime: &pluginsdk.SandboxRuntimeFacts{Os: "darwin", Architecture: "arm64", Transport: "ssh"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.False(t, pluginsdk.IsSandboxHostUnsupported(err), "an unsupported transport is not a host refusal")
}

func TestCompileDarwinGrantsNoSharedTemporaryDirectoryAndNoKeychain(t *testing.T) {
	req := darwinRequest(t)
	response, profile := compileDarwinProfile(t, req)
	tmp := req.References[0].Value
	require.Contains(t, profile.Filesystem.Allow, tmp)
	require.Contains(t, profile.Groups.Exclude, "system_write_macos", "the group that grants /private/tmp and /private/var/folders")
	for _, path := range append(append([]string{}, profile.Filesystem.Allow...), profile.Filesystem.Read...) {
		for _, shared := range deniedTemporaryRoots {
			require.NotEqual(t, shared, path)
		}
		require.NotContains(t, path, "Keychains")
		require.NotEqual(t, "/dev", path)
	}
	require.True(t, profile.Network.Block)
	require.Equal(t, map[string]string{"TMPDIR": ""}, profile.Environment.SetVars)
	require.Equal(t, []string{"environment", "set_vars", "TMPDIR"}, response.Compiled.Artifacts[0].Bindings[0].Path)
	require.Equal(t, "sandbox.child.tmp", response.Compiled.Artifacts[0].Bindings[0].RuntimeReference)
	require.NotContains(t, profile.Security, "approval_backends")
	require.NotContains(t, profile.Security, "approval_defaults")
	require.Equal(t, false, profile.Security["capability_elevation"])
	for _, binding := range response.Compiled.Artifacts[0].Bindings {
		require.NotEqual(t, approvalEndpoint, binding.RuntimeReference)
	}
	require.NotContains(t, response.Compiled.RequiredCapabilities, "approval_webhook")
}

func TestCompileDarwinIsDeterministicAndSorted(t *testing.T) {
	req := darwinRequest(t)
	first, profile := compileDarwinProfile(t, req)
	second, _ := compileDarwinProfile(t, req)
	require.Equal(t, first.Compiled.Artifacts[0].ContentUtf8, second.Compiled.Artifacts[0].ContentUtf8)
	require.IsNonDecreasing(t, profile.Filesystem.Allow)
	require.IsNonDecreasing(t, profile.Filesystem.Read)
	req.Policy.Grants.Filesystem = []*pluginsdk.SandboxFilesystemGrant{{Path: "/zzz"}, {Path: "/aaa"}, {Path: "/mmm", Writable: true}}
	_, profile = compileDarwinProfile(t, req)
	require.Equal(t, []string{"/aaa", "/zzz"}, profile.Filesystem.Read)
}

func TestCompileDarwinBindsTheAgentStateHomeAlongsideTheAttemptTemporaryDirectory(t *testing.T) {
	req := darwinRequest(t)
	home := "/Users/fixture/.kandev/agent-state"
	req.Policy.Grants.Filesystem = append(req.Policy.Grants.Filesystem, &pluginsdk.SandboxFilesystemGrant{Path: home, Writable: true})
	req.References = []*pluginsdk.SandboxRuntimeReference{
		{Key: "sandbox.child.home", Value: home},
		{Key: "sandbox.child.config", Value: filepath.Join(home, ".config")},
		{Key: "sandbox.child.state", Value: filepath.Join(home, ".local-state")},
		{Key: "sandbox.child.tmp", Value: attemptTmp},
	}
	_, profile := compileDarwinProfile(t, req)
	require.Len(t, profile.Environment.SetVars, 4)
	require.Contains(t, profile.Filesystem.Allow, req.References[3].Value)
}

func TestCompileDarwinRefusesBadTemporaryDirectories(t *testing.T) {
	for name, value := range map[string]string{"relative": "tmp", "shared": "/private/tmp/x", "var folders": "/private/var/folders/ab/x", "unclean": "/Users/x/../tmp", "tilde": "/Users/~/tmp", "root": "/tmp"} {
		req := darwinRequest(t)
		req.References[0].Value = value
		_, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
		require.Error(t, err, name)
	}
	req := darwinRequest(t)
	req.References = nil
	_, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.Error(t, err, "darwin always needs the attempt temporary directory")
	req = darwinRequest(t)
	req.Runtime.RuntimeDigest = runtimeDigest
	_, err = (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.Error(t, err, "the Linux digest does not pin the darwin runtime")
}

func TestCompileLinuxStillRefusesTheDarwinDigestAndTemporaryOnlyReferences(t *testing.T) {
	req := compileRequest(t)
	req.Runtime.RuntimeDigest = runtimeDigestDarwin
	_, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.Error(t, err)
	req = compileRequest(t)
	req.References = []*pluginsdk.SandboxRuntimeReference{{Key: "sandbox.child.tmp", Value: attemptTmp}}
	_, err = (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.Error(t, err)
}
