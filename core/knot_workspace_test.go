package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKnotWorkspaceHelper(t *testing.T, root string) string {
	t.Helper()
	helper := filepath.Join(root, "knot-workspace.sh")
	script := `#!/usr/bin/env bash
set -euo pipefail
root=""
platform=""
user_id=""
chat_id=""
name=""
group_name=""
identity_key=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) shift; root="$1" ;;
    --platform) shift; platform="$1" ;;
    --user-id) shift; user_id="$1" ;;
    --chat-id) shift; chat_id="$1" ;;
    --name) shift; name="$1" ;;
    --group-name) shift; group_name="$1" ;;
    --identity-key) shift; identity_key="$1" ;;
  esac
  shift
done
mkdir -p "$root/workspace/users/jane-example"
printf "platform=%s\nuser_id=%s\nchat_id=%s\nname=%s\ngroup_name=%s\nidentity_key=%s\n" "$platform" "$user_id" "$chat_id" "$name" "$group_name" "$identity_key" > "$root/call.log"
printf "export KNOT_ACTIVE_WORKSPACE='%s'\n" "$root/workspace/users/jane-example"
printf "export KNOT_USER_WORKSPACE='%s'\n" "$root/workspace/users/jane-example"
printf "export KNOT_GROUP_WORKSPACE='%s'\n" "$root/workspace/groups/product-room"
printf "export KNOT_CONVERSATION_DIR='%s'\n" "$root/workspace/conversations/feishu/oc_product"
printf "export KNOT_ACTOR_USER='jane-example'\n"
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return helper
}

func TestKnotWorkspaceResolverUsesHelperMetadata(t *testing.T) {
	root := t.TempDir()
	helper := writeKnotWorkspaceHelper(t, root)

	e := NewEngine("knot", &stubAgent{}, []Platform{&stubPlatformEngine{n: "feishu"}}, filepath.Join(root, "sessions.json"), LangEnglish)
	e.SetKnotWorkspace(helper, root)

	msg := &Message{
		SessionKey: "feishu:oc_product:ou_jane",
		Platform:   "feishu",
		UserID:     "ou_jane",
		UserName:   "Jane Example",
		ChatName:   "Product Room",
		ChannelKey: "oc_product",
	}

	resolution, err := e.resolveKnotWorkspace(msg)
	if err != nil {
		t.Fatalf("resolveKnotWorkspace() error: %v", err)
	}
	want := normalizeWorkspacePath(filepath.Join(root, "workspace", "users", "jane-example"))
	if resolution.workspace != want {
		t.Fatalf("workspace = %q, want %q", resolution.workspace, want)
	}
	env := envMap(resolution.env)
	if env["KNOT_GROUP_WORKSPACE"] != filepath.Join(root, "workspace", "groups", "product-room") {
		t.Fatalf("KNOT_GROUP_WORKSPACE env = %q", env["KNOT_GROUP_WORKSPACE"])
	}
	if env["KNOT_ACTOR_USER"] != "jane-example" {
		t.Fatalf("KNOT_ACTOR_USER env = %q", env["KNOT_ACTOR_USER"])
	}

	got, err := os.ReadFile(filepath.Join(root, "call.log"))
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	for _, wantLine := range []string{
		"platform=feishu",
		"user_id=ou_jane",
		"chat_id=oc_product",
		"name=Jane Example",
		"group_name=Product Room",
		"identity_key=feishu:user:ou_jane",
	} {
		if !strings.Contains(string(got), wantLine) {
			t.Fatalf("helper call log missing %q:\n%s", wantLine, got)
		}
	}
}

func envMap(entries []string) map[string]string {
	out := make(map[string]string)
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			out[key] = value
		}
	}
	return out
}

func TestCommandContextUsesKnotWorkspaceAgent(t *testing.T) {
	root := t.TempDir()
	helper := writeKnotWorkspaceHelper(t, root)

	agentName := "test-knot-workspace-agent"
	RegisterAgent(agentName, func(opts map[string]any) (Agent, error) {
		workDir, _ := opts["work_dir"].(string)
		return &namedStubWorkDirAgent{name: agentName, stubWorkDirAgent: stubWorkDirAgent{workDir: workDir}}, nil
	})

	baseAgent := &namedStubWorkDirAgent{name: agentName}
	e := NewEngine("knot", baseAgent, []Platform{&stubPlatformEngine{n: "feishu"}}, filepath.Join(root, "sessions.json"), LangEnglish)
	e.SetKnotWorkspace(helper, root)

	msg := &Message{
		SessionKey: "feishu:oc_product:ou_jane",
		Platform:   "feishu",
		UserID:     "ou_jane",
		UserName:   "Jane Example",
		ChatName:   "Product Room",
		ChannelKey: "oc_product",
	}

	agent, sessions, interactiveKey, workspace, err := e.commandContextWithWorkspace(&stubPlatformEngine{n: "feishu"}, msg)
	if err != nil {
		t.Fatalf("commandContextWithWorkspace() error: %v", err)
	}
	wantWorkspace := normalizeWorkspacePath(filepath.Join(root, "workspace", "users", "jane-example"))
	if workspace != wantWorkspace {
		t.Fatalf("workspace = %q, want %q", workspace, wantWorkspace)
	}
	if interactiveKey != wantWorkspace+":"+msg.SessionKey {
		t.Fatalf("interactiveKey = %q", interactiveKey)
	}
	if sessions == e.sessions {
		t.Fatal("expected workspace session manager, got global session manager")
	}
	gotAgent, ok := agent.(*namedStubWorkDirAgent)
	if !ok {
		t.Fatalf("agent type = %T, want *namedStubWorkDirAgent", agent)
	}
	if gotAgent.GetWorkDir() != wantWorkspace {
		t.Fatalf("agent workDir = %q, want %q", gotAgent.GetWorkDir(), wantWorkspace)
	}
}

func TestKnotWorkspaceEnvInjectedIntoAgentSession(t *testing.T) {
	root := t.TempDir()
	helper := writeKnotWorkspaceHelper(t, root)

	agentName := "test-knot-env-agent"
	RegisterAgent(agentName, func(opts map[string]any) (Agent, error) {
		workDir, _ := opts["work_dir"].(string)
		return &sessionEnvRecordingWorkDirAgent{
			sessionEnvRecordingAgent: sessionEnvRecordingAgent{session: newResultAgentSession("ok")},
			name:                     agentName,
			workDir:                  workDir,
		}, nil
	})

	baseAgent := &namedStubWorkDirAgent{name: agentName}
	p := &stubPlatformEngine{n: "feishu"}
	e := NewEngine("knot", baseAgent, []Platform{p}, filepath.Join(root, "sessions.json"), LangEnglish)
	e.SetKnotWorkspace(helper, root)

	msg := &Message{
		SessionKey: "feishu:oc_product:ou_jane",
		Platform:   "feishu",
		UserID:     "ou_jane",
		UserName:   "Jane Example",
		ChatName:   "Product Room",
		ChannelKey: "oc_product",
		Content:    "hello",
	}

	agent, sessions, interactiveKey, workspace, err := e.commandContextWithWorkspace(p, msg)
	if err != nil {
		t.Fatalf("commandContextWithWorkspace() error: %v", err)
	}
	session := sessions.GetOrCreateActive(msg.SessionKey)
	if !session.TryLock() {
		t.Fatal("session should lock")
	}
	e.processInteractiveMessageWith(p, msg, session, agent, sessions, interactiveKey, workspace, msg.SessionKey)

	envAgent, ok := agent.(*sessionEnvRecordingWorkDirAgent)
	if !ok {
		t.Fatalf("agent type = %T", agent)
	}
	if got := envAgent.EnvValue("KNOT_GROUP_WORKSPACE"); got != filepath.Join(root, "workspace", "groups", "product-room") {
		t.Fatalf("KNOT_GROUP_WORKSPACE = %q", got)
	}
	if got := envAgent.EnvValue("KNOT_CONVERSATION_DIR"); got != filepath.Join(root, "workspace", "conversations", "feishu", "oc_product") {
		t.Fatalf("KNOT_CONVERSATION_DIR = %q", got)
	}
	if got := envAgent.EnvValue("CC_SESSION_KEY"); got != msg.SessionKey {
		t.Fatalf("CC_SESSION_KEY = %q", got)
	}
}

type sessionEnvRecordingWorkDirAgent struct {
	sessionEnvRecordingAgent
	name    string
	workDir string
}

func (a *sessionEnvRecordingWorkDirAgent) Name() string { return a.name }
func (a *sessionEnvRecordingWorkDirAgent) SetWorkDir(dir string) {
	a.workDir = dir
}
func (a *sessionEnvRecordingWorkDirAgent) GetWorkDir() string {
	return a.workDir
}

func TestKnotWorkspaceIgnoresDirOverrides(t *testing.T) {
	root := t.TempDir()
	helper := writeKnotWorkspaceHelper(t, root)
	e := NewEngine("knot", &stubAgent{}, []Platform{&stubPlatformEngine{n: "feishu"}}, filepath.Join(root, "sessions.json"), LangEnglish)
	e.SetKnotWorkspace(helper, root)
	e.projectState = NewProjectStateStore(filepath.Join(root, "project-state.json"))

	workspace := normalizeWorkspacePath(filepath.Join(root, "workspace", "users", "jane-example"))
	override := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(override, 0o755); err != nil {
		t.Fatalf("mkdir override: %v", err)
	}
	e.projectState.SetWorkspaceDirOverride(workspace+":feishu:oc_product:ou_jane", override)
	if got := e.resolveChannelWorkDir(workspace, workspace+":feishu:oc_product:ou_jane"); got != workspace {
		t.Fatalf("resolveChannelWorkDir = %q, want %q", got, workspace)
	}
	errMsg, _ := e.dirApply(&stubWorkDirAgent{workDir: workspace}, NewSessionManager(filepath.Join(root, "sessions-2.json")), workspace+":feishu:oc_product:ou_jane", "feishu:oc_product:ou_jane", []string{override})
	if errMsg == "" {
		t.Fatal("dirApply should be disabled in Knot workspace mode")
	}
}

func TestParseKnotWorkspaceExportsUnquotesPaths(t *testing.T) {
	exports := parseKnotWorkspaceExports([]byte("export KNOT_ACTIVE_WORKSPACE='/tmp/root with spaces/user'\nexport QUOTED='it'\\''s ok'\n"))
	if exports["KNOT_ACTIVE_WORKSPACE"] != "/tmp/root with spaces/user" {
		t.Fatalf("KNOT_ACTIVE_WORKSPACE = %q", exports["KNOT_ACTIVE_WORKSPACE"])
	}
	if exports["QUOTED"] != "it's ok" {
		t.Fatalf("QUOTED = %q", exports["QUOTED"])
	}
}
