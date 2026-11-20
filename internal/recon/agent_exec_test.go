package recon

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func agentExecTestBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not available: %v", name, err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve absolute path for %s: %v", name, err)
	}
	return absolute
}

func agentExecTestRunner() AgentExecRunner {
	return AgentExecRunner{sandbox: directAgentExecSandbox{}}
}

type directAgentExecSandbox struct{}

func (directAgentExecSandbox) Name() string { return "test_direct" }

func (directAgentExecSandbox) Wrap(spec AgentExecSpec, argv []string, workDir string) (string, []string, error) {
	return spec.Binary, argv, nil
}

func agentExecTestSpec(t *testing.T, binary string) AgentExecSpec {
	t.Helper()
	return AgentExecSpec{
		ID: "test_tool", Language: AgentExecShell, Binary: binary,
		Network: AgentExecNetworkNone, Filesystem: AgentExecFilesystemEphemeralTmp,
		Timeout: 5 * time.Second, MaxStdoutBytes: 64 << 10, MaxStderrBytes: 64 << 10,
	}
}

func TestAgentExecSpecRejectsUnsafeMetadata(t *testing.T) {
	binary := agentExecTestBinary(t, "echo")
	tests := []struct {
		name   string
		mutate func(*AgentExecSpec)
		want   string
	}{
		{name: "empty id", mutate: func(spec *AgentExecSpec) { spec.ID = "" }, want: "non-empty"},
		{name: "padded id", mutate: func(spec *AgentExecSpec) { spec.ID = " test_tool " }, want: "non-empty"},
		{name: "unsupported language", mutate: func(spec *AgentExecSpec) { spec.Language = "ruby" }, want: "unsupported language"},
		{name: "empty binary", mutate: func(spec *AgentExecSpec) { spec.Binary = "" }, want: "absolute binary"},
		{name: "relative binary", mutate: func(spec *AgentExecSpec) { spec.Binary = "echo" }, want: "absolute binary"},
		{name: "unclean binary", mutate: func(spec *AgentExecSpec) { spec.Binary = "/bin/../bin/echo" }, want: "absolute binary"},
		{name: "missing network policy", mutate: func(spec *AgentExecSpec) { spec.Network = "" }, want: "network policy"},
		{name: "unsupported network policy", mutate: func(spec *AgentExecSpec) { spec.Network = "metered_proxy" }, want: "unsupported network policy"},
		{name: "missing filesystem policy", mutate: func(spec *AgentExecSpec) { spec.Filesystem = "" }, want: "filesystem policy"},
		{name: "unsupported filesystem policy", mutate: func(spec *AgentExecSpec) { spec.Filesystem = "read_write" }, want: "unsupported filesystem policy"},
		{name: "empty fixed argument", mutate: func(spec *AgentExecSpec) { spec.Argv = []string{""} }, want: "non-empty"},
		{name: "newline fixed argument", mutate: func(spec *AgentExecSpec) { spec.Argv = []string{"a\nb"} }, want: "line breaks"},
		{name: "command-string fixed argument", mutate: func(spec *AgentExecSpec) { spec.Argv = []string{"-c", "id"} }, want: "command-string"},
		{name: "combined command-string fixed argument", mutate: func(spec *AgentExecSpec) { spec.Argv = []string{"-ec"} }, want: "command-string"},
		{name: "command-string allowed argument", mutate: func(spec *AgentExecSpec) { spec.AllowedArgs = []string{"--command"} }, want: "command-string"},
		{name: "duplicate allowed argument", mutate: func(spec *AgentExecSpec) { spec.AllowedArgs = []string{"-n", "-n"} }, want: "more than once"},
		{name: "malformed env", mutate: func(spec *AgentExecSpec) { spec.Env = []string{"NOEQUALS"} }, want: "environment entries"},
		{name: "reserved env", mutate: func(spec *AgentExecSpec) { spec.Env = []string{"PATH=/tmp"} }, want: "reserved"},
		{name: "duplicate env", mutate: func(spec *AgentExecSpec) { spec.Env = []string{"A=1", "A=2"} }, want: "more than once"},
		{name: "newline env", mutate: func(spec *AgentExecSpec) { spec.Env = []string{"A=1\n2"} }, want: "line breaks"},
		{name: "zero timeout", mutate: func(spec *AgentExecSpec) { spec.Timeout = 0 }, want: "timeout"},
		{name: "excessive timeout", mutate: func(spec *AgentExecSpec) { spec.Timeout = agentExecMaxTimeout + time.Second }, want: "timeout"},
		{name: "zero stdout cap", mutate: func(spec *AgentExecSpec) { spec.MaxStdoutBytes = 0 }, want: "stdout cap"},
		{name: "excessive stdout cap", mutate: func(spec *AgentExecSpec) { spec.MaxStdoutBytes = agentExecMaxOutputBytes + 1 }, want: "stdout cap"},
		{name: "zero stderr cap", mutate: func(spec *AgentExecSpec) { spec.MaxStderrBytes = 0 }, want: "stderr cap"},
		{name: "stdin cap without stdin", mutate: func(spec *AgentExecSpec) { spec.MaxStdinBytes = 1 }, want: "stdin"},
		{name: "stdin enabled without cap", mutate: func(spec *AgentExecSpec) { spec.AllowStdin = true }, want: "stdin cap"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := agentExecTestSpec(t, binary)
			test.mutate(&spec)
			if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAgentExecRequestRejectsUnallowlistedArguments(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "echo"))
	spec.AllowedArgs = []string{"-n", "-v"}
	spec.AllowStdin = true
	spec.MaxStdinBytes = 16
	valid := AgentExecRequest{Args: []string{"-n"}, Stdin: []byte("x"), Timeout: time.Second}
	if err := spec.ValidateRequest(valid); err != nil {
		t.Fatalf("valid request was rejected: %v", err)
	}
	tooMany := make([]string, agentExecMaxArgs+1)
	for index := range tooMany {
		tooMany[index] = "-n"
	}
	tests := []struct {
		name    string
		request AgentExecRequest
		want    string
	}{
		{name: "unknown argument", request: AgentExecRequest{Args: []string{"-x"}}, want: "does not allow"},
		{name: "empty argument", request: AgentExecRequest{Args: []string{""}}, want: "non-empty"},
		{name: "newline argument", request: AgentExecRequest{Args: []string{"-n\n"}}, want: "line breaks"},
		{name: "too many arguments", request: AgentExecRequest{Args: tooMany}, want: "at most"},
		{name: "negative timeout", request: AgentExecRequest{Timeout: -time.Second}, want: "timeout"},
		{name: "timeout above spec", request: AgentExecRequest{Timeout: spec.Timeout + time.Second}, want: "timeout"},
		{name: "stdin too large", request: AgentExecRequest{Stdin: bytes.Repeat([]byte("a"), 17)}, want: "stdin exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := spec.ValidateRequest(test.request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateRequest error = %v, want %q", err, test.want)
			}
		})
	}
	noStdin := agentExecTestSpec(t, agentExecTestBinary(t, "echo"))
	if err := noStdin.ValidateRequest(AgentExecRequest{Stdin: []byte("x")}); err == nil || !strings.Contains(err.Error(), "does not accept stdin") {
		t.Fatalf("stdin rejection = %v, want a disabled-stdin error", err)
	}
}

func TestAgentExecCommandStringRulesFollowTheInterpreterClass(t *testing.T) {
	binary := agentExecTestBinary(t, "echo")
	goSpec := agentExecTestSpec(t, binary)
	goSpec.Language = AgentExecGo
	goSpec.AllowedArgs = []string{"-c"}
	if err := goSpec.Validate(); err != nil {
		t.Fatalf("non-interpreter spec rejected a legitimate -c flag: %v", err)
	}
	pythonSpec := agentExecTestSpec(t, binary)
	pythonSpec.Language = AgentExecPython
	pythonSpec.AllowedArgs = []string{"-ec"}
	if err := pythonSpec.Validate(); err == nil || !strings.Contains(err.Error(), "command-string") {
		t.Fatalf("python spec error = %v, want a command-string rejection", err)
	}
}

func TestAgentExecRunsReviewedInterpreterScripts(t *testing.T) {
	tests := []struct {
		name     string
		binary   string
		language AgentExecLanguage
		file     string
		content  string
		want     string
	}{
		{name: "shell", binary: "sh", language: AgentExecShell, file: "reviewed.sh", content: "echo script-ok\n", want: "script-ok\n"},
		{name: "python", binary: "python3", language: AgentExecPython, file: "reviewed.py", content: "print('python-ok')\n", want: "python-ok\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), test.file)
			if err := os.WriteFile(script, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			spec := agentExecTestSpec(t, agentExecTestBinary(t, test.binary))
			spec.Language = test.language
			spec.Argv = []string{script}
			result, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if string(result.Stdout) != test.want {
				t.Fatalf("stdout = %q, want %q", result.Stdout, test.want)
			}
		})
	}
}

func TestAgentExecRejectsInvalidSpecBeforeStartingAProcess(t *testing.T) {
	spec := agentExecTestSpec(t, "echo")
	if _, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{}); !errors.Is(err, ErrAgentExecRejected) {
		t.Fatalf("Execute error = %v, want ErrAgentExecRejected", err)
	}
}

func TestAgentExecRunsLiterallyWithoutShellInterpretation(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "echo"))
	spec.Argv = []string{"literal"}
	spec.AllowedArgs = []string{"$(id)"}
	result, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{Args: []string{"$(id)"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "literal $(id)\n" {
		t.Fatalf("stdout = %q, want a literal unexpanded argument", result.Stdout)
	}
	if result.ExitCode != 0 || result.TimedOut || result.Canceled || result.StdoutTruncated {
		t.Fatalf("unexpected result metadata: %+v", result)
	}
}

func TestAgentExecReturnsNonZeroExitCode(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "false"))
	result, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{})
	if !errors.Is(err, ErrAgentExecExit) {
		t.Fatalf("Execute error = %v, want ErrAgentExecExit", err)
	}
	if result.ExitCode == 0 || result.TimedOut || result.Canceled {
		t.Fatalf("unexpected result metadata: %+v", result)
	}
}

func TestAgentExecBoundsStdoutAndStderr(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "cat"))
	spec.AllowStdin = true
	spec.MaxStdinBytes = 1024
	spec.MaxStdoutBytes = 16
	result, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{
		Stdin: bytes.Repeat([]byte("a"), 1024),
	})
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Execute error = %v, want ErrOutputLimit", err)
	}
	if !result.StdoutTruncated || len(result.Stdout) != 16 {
		t.Fatalf("stdout was not capped: truncated=%t bytes=%d", result.StdoutTruncated, len(result.Stdout))
	}
}

func TestAgentExecTimesOutAndKillsTheProcess(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "sleep"))
	spec.AllowedArgs = []string{"30"}
	result, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{
		Args: []string{"30"}, Timeout: 100 * time.Millisecond,
	})
	if !errors.Is(err, ErrAgentExecTimeout) {
		t.Fatalf("Execute error = %v, want ErrAgentExecTimeout", err)
	}
	if !result.TimedOut || result.Duration > 5*time.Second {
		t.Fatalf("unexpected timeout metadata: %+v", result)
	}
}

func TestAgentExecHonorsCallerCancellation(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "sleep"))
	spec.AllowedArgs = []string{"30"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(50*time.Millisecond, cancel)
	result, err := agentExecTestRunner().Execute(ctx, spec, AgentExecRequest{Args: []string{"30"}})
	if !errors.Is(err, ErrAgentExecCanceled) {
		t.Fatalf("Execute error = %v, want ErrAgentExecCanceled", err)
	}
	if !result.Canceled || result.Duration > 5*time.Second {
		t.Fatalf("unexpected cancellation metadata: %+v", result)
	}
}

func TestAgentExecSanitizesEnvironmentAndAppliesReviewedEntries(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_SECRET", "leaked")
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "env"))
	spec.Env = []string{"HEIMDALL_TEST_FLAG=on"}
	result, err := agentExecTestRunner().Execute(context.Background(), spec, AgentExecRequest{})
	if err != nil {
		t.Fatal(err)
	}
	output := string(result.Stdout)
	if !strings.Contains(output, "HEIMDALL_TEST_FLAG=on") {
		t.Fatalf("reviewed environment entry is missing: %s", output)
	}
	if strings.Contains(output, "HEIMDALL_TEST_SECRET") {
		t.Fatalf("host secret leaked into the child environment: %s", output)
	}
}

func TestAgentExecEnvironmentIsDeterministicAndOverridesBase(t *testing.T) {
	environment := agentExecEnvironment([]string{"B=2", "A=1"}, []string{"A=3", "C=4"})
	if strings.Join(environment, ",") != "A=3,B=2,C=4" {
		t.Fatalf("environment = %v, want sorted overrides", environment)
	}
}

func TestAgentExecFailsClosedWithoutSandbox(t *testing.T) {
	spec := agentExecTestSpec(t, agentExecTestBinary(t, "echo"))
	if _, err := (AgentExecRunner{}).Execute(context.Background(), spec, AgentExecRequest{}); !errors.Is(err, ErrAgentExecSandboxUnavailable) {
		t.Fatalf("Execute error = %v, want ErrAgentExecSandboxUnavailable", err)
	}
}

func TestAgentExecPlatformSandboxConfinesNetworkAndWrites(t *testing.T) {
	runner := NewAgentExecRunner()
	if runner.sandbox == nil {
		t.Skip("no reviewed sandbox is available on this host")
	}
	python := agentExecTestBinary(t, "python3")
	script := filepath.Join(t.TempDir(), "sandbox_probe.py")
	content := `import os, socket, sys

cwd = os.getcwd()
print("cwd=" + cwd)
print("home=" + os.environ.get("HOME", ""))
print("tmpdir=" + os.environ.get("TMPDIR", ""))

try:
    with open(os.path.join(cwd, "allowed.txt"), "w") as handle:
        handle.write("ok")
    print("write-workdir=ok")
except Exception as exc:
    print("write-workdir=blocked:" + type(exc).__name__)

try:
    with open(sys.argv[1], "w") as handle:
        handle.write("bad")
    print("write-outside=allowed")
except Exception as exc:
    print("write-outside=blocked:" + type(exc).__name__)

try:
    connection = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=1)
    connection.close()
    print("network=connected")
except Exception as exc:
    print("network=blocked:" + type(exc).__name__)
`
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	spec := agentExecTestSpec(t, python)
	spec.Language = AgentExecPython
	spec.Argv = []string{script}
	spec.AllowedArgs = []string{outside, host, port}
	result, err := runner.Execute(context.Background(), spec, AgentExecRequest{Args: []string{outside, host, port}})
	if err != nil {
		t.Fatal(err)
	}
	output := string(result.Stdout)
	for _, expected := range []string{"write-workdir=ok", "write-outside=blocked:", "network=blocked:"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("sandboxed output omitted %q:\n%s", expected, output)
		}
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sandbox allowed a write outside the work dir: %v", err)
	}
	workDir := agentExecTestOutputValue(output, "cwd=")
	if workDir == "" {
		t.Fatalf("sandboxed output omitted the work dir:\n%s", output)
	}
	if _, err := os.Stat(workDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ephemeral work dir was not removed: %v", err)
	}
	if home := agentExecTestOutputValue(output, "home="); home != workDir {
		t.Fatalf("HOME = %q, want the ephemeral work dir %q", home, workDir)
	}
	if tmp := agentExecTestOutputValue(output, "tmpdir="); tmp != workDir {
		t.Fatalf("TMPDIR = %q, want the ephemeral work dir %q", tmp, workDir)
	}
	if result.Sandbox == "" || result.Sandbox == "test_direct" {
		t.Fatalf("result recorded an unreviewed sandbox: %q", result.Sandbox)
	}
}

func agentExecTestOutputValue(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}
