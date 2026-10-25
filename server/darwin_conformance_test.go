package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
)

// The canaries run the provider-compiled darwin profile against the pinned
// runtime. Every result is allowed, denied, control_failed, error or skipped,
// with an exit code. Nothing printed names a real file or carries content.
const (
	canaryBound   = 10 * time.Second
	markerPrefix  = ".kandev-conformance-"
	keychainLabel = "kandev-conformance-service"
)

type canaryResult string

const (
	resultAllowed       canaryResult = "allowed"
	resultDenied        canaryResult = "denied"
	resultControlFailed canaryResult = "control_failed"
	resultError         canaryResult = "error"
	resultSkipped       canaryResult = "skipped"
)

type canaryRun struct {
	exit  int
	fault bool // a signal or a timeout
}

func (r canaryRun) result(control bool) canaryResult {
	switch {
	case r.fault:
		return resultError
	case r.exit == 0:
		return resultAllowed
	case r.exit == 10 && !control:
		return resultDenied
	}
	return resultError
}

type canary struct {
	name   string
	args   []string
	expect canaryResult
	// skipUnless is a real host target that may be absent; the canary then
	// reports skipped and its role is covered by a fixture canary.
	skipUnless string
}

func requireDarwinHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("the darwin conformance suite runs on macOS arm64 only")
	}
}

// purgeStaleRoots removes marker roots whose owning process is gone.
func purgeStaleRoots(home string) {
	entries, _ := os.ReadDir(home)
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(markerPrefix) + `p(\d+)-`)
	for _, entry := range entries {
		match := pattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		pid, _ := strconv.Atoi(match[1])
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			_ = os.RemoveAll(filepath.Join(home, entry.Name()))
		}
	}
}

// fixtureRoot creates the marker-named root under the user's home, outside
// every denied temporary root, and removes it on success, failure, panic and
// SIGINT or SIGTERM.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	purgeStaleRoots(home)
	root, err := os.MkdirTemp(home, markerPrefix+"p"+strconv.Itoa(os.Getpid())+"-")
	require.NoError(t, err)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if _, ok := <-signals; ok {
			_ = os.RemoveAll(root)
			os.Exit(130)
		}
	}()
	t.Cleanup(func() {
		signal.Stop(signals)
		close(signals)
		_ = os.RemoveAll(root)
	})
	return root
}

func darwinRuntimeBinary(t *testing.T, root string) string {
	t.Helper()
	path := os.Getenv("NONO_ACCEPTANCE_BINARY")
	if path == "" {
		path = filepath.Join(root, "nono")
		command := exec.Command("python3", filepath.Join("..", "scripts", "runtime_package.py"), "prepare", path, "darwin-arm64")
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
	}
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	digest := sha256.Sum256(content)
	require.Equal(t, runtimeDigestDarwin, hex.EncodeToString(digest[:]), "the suite runs only the pinned darwin runtime")
	return path
}

type darwinHarness struct {
	t       *testing.T
	root    string
	nono    string
	helper  string
	work    string
	profile string
	tmp     string
}

func (h *darwinHarness) run(ctx context.Context, sandboxed bool, stdin string, args ...string) (canaryRun, []byte, int) {
	ctx, cancel := context.WithTimeout(ctx, canaryBound)
	defer cancel()
	var command *exec.Cmd
	if sandboxed {
		command = exec.CommandContext(ctx, h.nono, append([]string{"run", "--silent", "--profile", h.profile, "--", h.helper}, args...)...)
	} else {
		command = exec.CommandContext(ctx, h.helper, args...)
	}
	command.Dir = h.work
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = time.Second
	command.Env = []string{"HOME=" + filepath.Join(h.root, "home"), "TMPDIR=" + h.tmp, "PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1"}
	command.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	err := command.Start()
	if err != nil {
		return canaryRun{fault: true}, nil, 0
	}
	wrapper := command.Process.Pid
	err = command.Wait()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return canaryRun{}, stdout.Bytes(), wrapper
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		return canaryRun{exit: exit.ExitCode()}, stdout.Bytes(), wrapper
	}
	return canaryRun{fault: true}, stdout.Bytes(), wrapper
}

// compile builds the provider profile for the harness grants and applies the
// per-attempt bindings the host would apply.
func (h *darwinHarness) compile(egress string, mcp *pluginsdk.SandboxEndpoint) {
	t := h.t
	req := &pluginsdk.CompileSandboxPolicyRequest{Context: requestContext(), Runtime: darwinFacts(),
		References: []*pluginsdk.SandboxRuntimeReference{{Key: "sandbox.child.tmp", Value: h.tmp}},
		Policy: &pluginsdk.SandboxPolicySnapshot{PolicyId: "policy", Revision: 1, Digest: "digest", CeilingDigest: "ceiling", Grants: &pluginsdk.SandboxGrants{
			Filesystem: []*pluginsdk.SandboxFilesystemGrant{{Path: h.work, Writable: true}, {Path: h.helper}},
		}}}
	if mcp != nil {
		req.Policy.Grants.KandevMcp = true
		req.Endpoints = []*pluginsdk.SandboxEndpoint{mcp}
	}
	response, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.NoError(t, err)
	artifact := response.Compiled.Artifacts[0]
	var profile map[string]any
	require.NoError(t, json.Unmarshal([]byte(artifact.ContentUtf8), &profile))
	values := map[string]string{"sandbox.child.tmp": h.tmp, "sandbox.egress.endpoint": egress}
	for _, binding := range artifact.Bindings {
		node := profile
		for _, key := range binding.Path[:len(binding.Path)-1] {
			node = node[key].(map[string]any)
		}
		node[binding.Path[len(binding.Path)-1]] = values[binding.RuntimeReference]
	}
	content, err := json.Marshal(profile)
	require.NoError(t, err)
	h.profile = filepath.Join(h.root, "profile.json")
	require.NoError(t, os.WriteFile(h.profile, content, 0o600))
}

func listen(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().String()
}

func writeFixture(t *testing.T, path string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("synthetic fixture content"), 0o600))
	return path
}

// createKeychain makes a throwaway keychain file that is never added to the
// search list. The login keychain is never read, modified or unlocked.
func createKeychain(t *testing.T, path string) {
	t.Helper()
	for _, args := range [][]string{
		{"create-keychain", "-p", "synthetic", path},
		{"add-generic-password", "-a", "account", "-s", keychainLabel, "-w", "synthetic-secret", path},
	} {
		output, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
		require.NoError(t, err, "keychain setup failed: %d bytes of output withheld", len(output))
	}
}

func macOSVersion() string {
	output, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func TestSandboxDarwinConformance(t *testing.T) {
	requireDarwinHost(t)
	root := fixtureRoot(t)
	h := &darwinHarness{t: t, root: root, nono: darwinRuntimeBinary(t, root), work: filepath.Join(root, "work"), tmp: filepath.Join(root, "attempt", "tmp")}
	for _, dir := range []string{h.work, h.tmp, filepath.Join(root, "home")} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	h.helper = filepath.Join(root, "canary")
	build := exec.Command("go", "build", "-o", h.helper, "./testdata/canary")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))

	outsideDir := filepath.Join(root, "outside")
	fixtures := map[string]string{
		"other_home":   writeFixture(t, filepath.Join(root, "other-home", "secret.txt")),
		"other_work":   writeFixture(t, filepath.Join(root, "other-worktree", "file.txt")),
		"ssh_fixture":  writeFixture(t, filepath.Join(root, "fixture-home", ".ssh", "id_fixture")),
		"browser_data": writeFixture(t, filepath.Join(root, "fixture-home", "Library", "browser", "Cookies")),
	}
	keychain := filepath.Join(root, "throwaway.keychain-db")
	createKeychain(t, keychain)

	direct, other := listen(t), listen(t)
	// The working MCP relay route: a loopback endpoint the child reaches only through the proxy.
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer relay.Close()
	relayURL, err := url.Parse(relay.URL)
	require.NoError(t, err)
	relayPort, err := strconv.Atoi(relayURL.Port())
	require.NoError(t, err)
	egress := fixtureEgress(t, relay.URL)
	h.compile(egress, &pluginsdk.SandboxEndpoint{Key: "kandev.mcp", Host: "127.0.0.1", Port: uint32(relayPort), Scheme: "http", Path: "/mcp"})

	home, _ := os.UserHomeDir()
	tmpMarker := "/private/tmp/" + filepath.Base(root) + "-canary"
	t.Cleanup(func() { _ = os.Remove(tmpMarker) })
	canaries := []canary{
		{name: "other_home_directory", args: []string{"read", fixtures["other_home"]}, expect: resultDenied},
		{name: "other_task_worktree", args: []string{"read", fixtures["other_work"]}, expect: resultDenied},
		{name: "tmp_write", args: []string{"write", tmpMarker}, expect: resultDenied},
		{name: "ssh_listing", args: []string{"list", filepath.Join(home, ".ssh")}, expect: resultDenied, skipUnless: filepath.Join(home, ".ssh")},
		{name: "ssh_fixture_listing", args: []string{"list", filepath.Dir(fixtures["ssh_fixture"])}, expect: resultDenied},
		{name: "browser_data_listing", args: []string{"list", filepath.Join(home, "Library", "Application Support", "Google", "Chrome")}, expect: resultDenied, skipUnless: filepath.Join(home, "Library", "Application Support", "Google", "Chrome")},
		{name: "browser_data_fixture_listing", args: []string{"list", filepath.Dir(fixtures["browser_data"])}, expect: resultDenied},
		{name: "keychain_item", args: []string{"keychain", keychain, keychainLabel}, expect: resultDenied},
		{name: "write_outside_granted", args: []string{"write", filepath.Join(outsideDir, "file.txt")}, expect: resultDenied},
		{name: "write_inside_work", args: []string{"write", filepath.Join(h.work, "allowed.txt")}, expect: resultAllowed},
		{name: "direct_loopback_egress", args: []string{"dial", direct}, expect: resultDenied},
		{name: "arbitrary_loopback_port", args: []string{"dial", other}, expect: resultDenied},
		{name: "mcp_relay_route", args: []string{"proxy-get", relay.URL + "/mcp"}, expect: resultAllowed},
	}
	require.NoError(t, os.MkdirAll(outsideDir, 0o700))
	failed := 0
	report := []string{}
	for _, c := range canaries {
		line := h.exercise(c, relay.URL)
		report = append(report, line.text)
		if line.failed {
			failed++
		}
	}
	h.stdio(t, &report, &failed, fixtures["other_home"])
	h.ownership(t, &report, &failed)
	t.Logf("macOS %s darwin conformance (nono %s)\n%s", macOSVersion(), runtimeVersion, strings.Join(report, "\n"))
	require.Zero(t, failed, "a canary did not report the expected result")
}

type canaryLine struct {
	text   string
	failed bool
}

func (h *darwinHarness) exercise(c canary, relayURL string) canaryLine {
	if c.skipUnless != "" {
		if _, err := os.Stat(c.skipUnless); err != nil {
			return canaryLine{text: fmt.Sprintf("%-32s %s", c.name, resultSkipped)}
		}
	}
	ctx := context.Background()
	controlArgs := c.args
	if c.args[0] == "proxy-get" {
		controlArgs = []string{"proxy-get-direct", c.args[1]}
	}
	control, _, _ := h.runControl(ctx, controlArgs)
	controlResult := control.result(true)
	sandboxed, _, _ := h.run(ctx, true, "", c.args...)
	got := sandboxed.result(false)
	line := fmt.Sprintf("%-32s control=%s sandbox=%s exit=%d", c.name, controlResult, got, sandboxed.exit)
	if controlResult != resultAllowed {
		return canaryLine{text: line + " " + string(resultControlFailed), failed: true}
	}
	return canaryLine{text: line, failed: got != c.expect}
}

// runControl performs the same operation outside the sandbox. A proxy canary's
// control reaches its destination directly.
func (h *darwinHarness) runControl(ctx context.Context, args []string) (canaryRun, []byte, int) {
	if args[0] == "proxy-get-direct" {
		response, err := (&http.Client{Timeout: 4 * time.Second}).Get(args[1])
		if err != nil {
			return canaryRun{exit: 11}, nil, 0
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return canaryRun{}, nil, 0
		}
		return canaryRun{exit: 11}, nil, 0
	}
	return h.run(ctx, false, "", args...)
}

// stdio proves ACP stdio passes unchanged: zero non-JSON stdout lines, with and
// without a denial while the stream is open.
func (h *darwinHarness) stdio(t *testing.T, report *[]string, failed *int, deniedPath string) {
	t.Helper()
	for _, c := range []struct {
		name string
		args []string
	}{{"acp_stdio_round_trip", []string{"stdio"}}, {"acp_stdio_during_denial", []string{"stdio", deniedPath}}} {
		control, controlOut, _ := h.run(context.Background(), false, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n", c.args...)
		sandboxed, out, _ := h.run(context.Background(), true, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n", c.args...)
		ok := control.result(true) == resultAllowed && sandboxed.result(false) == resultAllowed && jsonLines(controlOut) == 1 && jsonLines(out) == 1 && nonJSONLines(out) == 0
		*report = append(*report, fmt.Sprintf("%-32s control=%s sandbox=%s non_json_lines=%d", c.name, control.result(true), sandboxed.result(false), nonJSONLines(out)))
		if !ok {
			*failed++
		}
	}
}

func jsonLines(data []byte) int {
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if json.Valid(scanner.Bytes()) {
			count++
		}
	}
	return count
}

func nonJSONLines(data []byte) int {
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if !json.Valid(scanner.Bytes()) {
			count++
		}
	}
	return count
}

// ownership proves the sandboxed child stays in the wrapper's process group,
// the premise of the process-tree ownership model.
func (h *darwinHarness) ownership(t *testing.T, report *[]string, failed *int) {
	t.Helper()
	run, out, wrapper := h.run(context.Background(), true, "", "group")
	var reply struct{ Pgid int }
	ok := run.result(false) == resultAllowed && json.Unmarshal(out, &reply) == nil && reply.Pgid == wrapper
	*report = append(*report, fmt.Sprintf("%-32s sandbox=%s child_group_equals_wrapper=%t", "ownership", run.result(false), ok))
	if !ok {
		*failed++
	}
}
