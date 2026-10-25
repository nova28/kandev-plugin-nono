package main

import (
	"path/filepath"
	"strings"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var childDirectories = []struct{ key, name string }{
	{"sandbox.child.home", "HOME"},
	{"sandbox.child.config", "XDG_CONFIG_HOME"},
	{"sandbox.child.state", "XDG_STATE_HOME"},
	{"sandbox.child.tmp", "TMPDIR"},
}

func compileChildDirectories(req *pluginsdk.CompileSandboxPolicyRequest, darwin bool) (map[string]string, []*pluginsdk.SandboxArtifactBinding, error) {
	if len(req.References) == 0 {
		return nil, nil, nil
	}
	values := map[string]string{}
	for _, ref := range req.References {
		if ref == nil || values[ref.Key] != "" || !filepath.IsAbs(ref.Value) || filepath.Clean(ref.Value) != ref.Value || strings.ContainsAny(ref.Value, "$~\x00\r\n") {
			return nil, nil, status.Error(codes.InvalidArgument, "invalid child directory reference")
		}
		values[ref.Key] = ref.Value
	}
	home := values["sandbox.child.home"]
	if len(values) != len(childDirectories) || !grantedChildHome(home, req.Policy.Grants.Filesystem) {
		return nil, nil, status.Error(codes.InvalidArgument, "child state requires an explicit filesystem grant")
	}
	environment := map[string]string{}
	bindings := make([]*pluginsdk.SandboxArtifactBinding, 0, len(childDirectories))
	for _, dir := range childDirectories {
		value := values[dir.key]
		if !(darwin && dir.key == "sandbox.child.tmp") && value != home && !strings.HasPrefix(value, home+string(filepath.Separator)) {
			return nil, nil, status.Error(codes.InvalidArgument, "child directories must share the granted home")
		}
		environment[dir.name] = ""
		bindings = append(bindings, &pluginsdk.SandboxArtifactBinding{Path: []string{"environment", "set_vars", dir.name}, RuntimeReference: dir.key})
	}
	return environment, bindings, nil
}

func grantedChildHome(home string, grants []*pluginsdk.SandboxFilesystemGrant) bool {
	if home == "" {
		return false
	}
	for _, grant := range grants {
		if grant != nil && (home == grant.Path || strings.HasPrefix(home, grant.Path+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
