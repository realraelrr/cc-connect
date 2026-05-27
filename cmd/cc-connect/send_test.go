package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chenhg5/cc-connect/core"
)

func TestParseSendArgs_AttachmentsWithoutMessage(t *testing.T) {
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "chart.png")
	docPath := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(imgPath, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, 0o644); err != nil {
		t.Fatalf("write image: %v", err)
	}
	if err := os.WriteFile(docPath, []byte("hello report"), 0o644); err != nil {
		t.Fatalf("write doc: %v", err)
	}

	req, dataDir, err := parseSendArgs([]string{"--image", imgPath, "--file", docPath})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if dataDir != "" {
		t.Fatalf("dataDir = %q, want empty", dataDir)
	}
	if req.Message != "" {
		t.Fatalf("message = %q, want empty", req.Message)
	}
	if len(req.Images) != 1 {
		t.Fatalf("images len = %d, want 1", len(req.Images))
	}
	if req.Images[0].FileName != "chart.png" {
		t.Fatalf("image filename = %q, want chart.png", req.Images[0].FileName)
	}
	if req.Images[0].MimeType != "image/png" {
		t.Fatalf("image mime = %q, want image/png", req.Images[0].MimeType)
	}
	if len(req.Files) != 1 {
		t.Fatalf("files len = %d, want 1", len(req.Files))
	}
	if req.Files[0].FileName != "report.txt" {
		t.Fatalf("file filename = %q, want report.txt", req.Files[0].FileName)
	}
}

func TestParseSendArgs_RequiresMessageOrAttachment(t *testing.T) {
	_, _, err := parseSendArgs(nil)
	if err == nil {
		t.Fatal("expected error for empty send args")
	}
}

func TestParseSendArgs_UsesSessionEnvFallback(t *testing.T) {
	t.Setenv("CC_PROJECT", "demo")
	t.Setenv("CC_SESSION_KEY", "telegram:123:456")

	dir := t.TempDir()
	imgPath := filepath.Join(dir, "chart.png")
	if err := os.WriteFile(imgPath, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, 0o644); err != nil {
		t.Fatalf("write image: %v", err)
	}

	req, _, err := parseSendArgs([]string{"--image", imgPath})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if req.Project != "demo" {
		t.Fatalf("project = %q, want demo", req.Project)
	}
	if req.SessionKey != "telegram:123:456" {
		t.Fatalf("session = %q, want telegram:123:456", req.SessionKey)
	}
}

func TestDetectAttachmentMimeType_UsesExtensionFallback(t *testing.T) {
	mimeType := detectAttachmentMimeType("note.md", []byte("plain"))
	if mimeType != "text/markdown; charset=utf-8" && mimeType != "text/markdown" {
		t.Fatalf("mimeType = %q, want markdown mime", mimeType)
	}
}

func TestReadAttachment_SizeLimit(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(small, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readAttachment(small, "file"); err != nil {
		t.Fatalf("small file should succeed: %v", err)
	}

	big := filepath.Join(dir, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAttachmentSize + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if _, _, _, err := readAttachment(big, "file"); err == nil {
		t.Fatal("oversized file should be rejected")
	}
}

func TestReadAttachment_CleanPath(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "test.txt")
	if err := os.WriteFile(f, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Path with ../ should still work after cleaning
	dirty := filepath.Join(sub, "..", "sub", "test.txt")
	data, name, _, err := readAttachment(dirty, "file")
	if err != nil {
		t.Fatalf("readAttachment with dirty path: %v", err)
	}
	if string(data) != "ok" {
		t.Errorf("unexpected data: %q", data)
	}
	if name != "test.txt" {
		t.Errorf("unexpected filename: %q", name)
	}
}

func TestReadAttachment_EnforcesKnotDeliverablesBoundary(t *testing.T) {
	root := t.TempDir()
	userWorkspace := filepath.Join(root, "workspace", "users", "example-user")
	deliverable := filepath.Join(userWorkspace, "deliverables", "report.txt")
	secret := filepath.Join(root, "runtime", ".env")
	conversationDir := filepath.Join(root, "workspace", "conversations", "feishu", "chat_aaaaaaaaaaaaaaaaaaaaaaaa")
	for _, dir := range []string{filepath.Dir(deliverable), filepath.Dir(secret), conversationDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(deliverable, []byte("report"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("token=secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KNOT_ROOT", root)
	t.Setenv("KNOT_SCOPE", "direct")
	t.Setenv("KNOT_PLATFORM", "feishu")
	t.Setenv("KNOT_CHAT_ID_HASH", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("KNOT_PLATFORM_USER_ID_HASH", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	t.Setenv("KNOT_IDENTITY_KEY_HASH", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	t.Setenv("KNOT_CONVERSATION_DIR", conversationDir)
	t.Setenv("KNOT_ACTOR_USER", "example-user")
	t.Setenv("KNOT_USER_WORKSPACE", userWorkspace)

	if _, _, _, err := readAttachment(deliverable, "file"); err != nil {
		t.Fatalf("Knot deliverable should be readable: %v", err)
	}
	if _, _, _, err := readAttachment(secret, "file"); err == nil {
		t.Fatal("Knot runtime secret path should be rejected")
	}
	eventLog := filepath.Join(conversationDir, "events.jsonl")
	if data, err := os.ReadFile(eventLog); err != nil || !strings.Contains(string(data), `"reason_code":"outside_deliverables"`) {
		t.Fatalf("expected outside_deliverables audit event, data=%q err=%v", data, err)
	}
	hardlinkPath := filepath.Join(userWorkspace, "deliverables", "env.txt")
	if err := os.Link(secret, hardlinkPath); err != nil {
		t.Skipf("filesystem refused hardlink: %v", err)
	}
	if _, _, _, err := readAttachment(hardlinkPath, "file"); err == nil {
		t.Fatal("Knot hardlinked deliverable should be rejected")
	}
	if data, err := os.ReadFile(eventLog); err != nil || !strings.Contains(string(data), `"reason_code":"hardlink_denied"`) {
		t.Fatalf("expected hardlink_denied audit event, data=%q err=%v", data, err)
	}
}

func TestBuildSendPayload_JSONRoundTrip(t *testing.T) {
	req := core.SendRequest{
		Project:    "demo",
		SessionKey: "telegram:1:2",
		Message:    "done",
		Images: []core.ImageAttachment{{
			MimeType: "image/png",
			Data:     []byte("img"),
			FileName: "a.png",
		}},
		Files: []core.FileAttachment{{
			MimeType: "text/plain",
			Data:     []byte("doc"),
			FileName: "a.txt",
		}},
	}

	body, err := buildSendPayload(req)
	if err != nil {
		t.Fatalf("buildSendPayload returned error: %v", err)
	}

	var decoded core.SendRequest
	if err := decodeSendPayload(body, &decoded); err != nil {
		t.Fatalf("decodeSendPayload returned error: %v", err)
	}
	if len(decoded.Images) != 1 || string(decoded.Images[0].Data) != "img" {
		t.Fatalf("decoded images = %#v", decoded.Images)
	}
	if len(decoded.Files) != 1 || string(decoded.Files[0].Data) != "doc" {
		t.Fatalf("decoded files = %#v", decoded.Files)
	}
}
