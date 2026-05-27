package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type knotAuditContext struct {
	Root               string
	ConversationDir    string
	Platform           string
	Scope              string
	ChatIDHash         string
	PlatformUserIDHash string
	IdentityKeyHash    string
	ActorUser          string
	GroupSlug          string
	UserWorkspace      string
	GroupWorkspace     string
	CodexSessionID     string
}

type knotAuditEvent struct {
	SchemaVersion      string `json:"schema_version"`
	Time               string `json:"time"`
	Event              string `json:"event"`
	Platform           string `json:"platform"`
	ChatIDHash         string `json:"chat_id_hash"`
	PlatformUserIDHash string `json:"platform_user_id_hash"`
	IdentityKeyHash    string `json:"identity_key_hash"`
	ActorUser          string `json:"actor_user"`
	GroupSlug          string `json:"group_slug"`
	CodexSessionID     string `json:"codex_session_id"`
	Status             string `json:"status"`
	ReasonCode         string `json:"reason_code"`
	ResourceKind       string `json:"resource_kind"`
	ResourcePath       string `json:"resource_path"`
	ResourceSHA256     string `json:"resource_sha256"`
	ResourceSizeBytes  int64  `json:"resource_size_bytes"`
}

type knotAuditResource struct {
	Kind string
	Path string
	Data []byte
}

func knotAuditContextFromEnv(env []string) *knotAuditContext {
	values := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	dir := strings.TrimSpace(values["KNOT_CONVERSATION_DIR"])
	if dir == "" {
		return nil
	}
	ctx := &knotAuditContext{
		Root:               strings.TrimSpace(values["KNOT_ROOT"]),
		ConversationDir:    dir,
		Platform:           strings.TrimSpace(values["KNOT_PLATFORM"]),
		Scope:              strings.TrimSpace(values["KNOT_SCOPE"]),
		ChatIDHash:         strings.TrimSpace(values["KNOT_CHAT_ID_HASH"]),
		PlatformUserIDHash: strings.TrimSpace(values["KNOT_PLATFORM_USER_ID_HASH"]),
		IdentityKeyHash:    strings.TrimSpace(values["KNOT_IDENTITY_KEY_HASH"]),
		ActorUser:          strings.TrimSpace(values["KNOT_ACTOR_USER"]),
		GroupSlug:          firstNonEmpty(strings.TrimSpace(values["KNOT_GROUP_SLUG"]), strings.TrimSpace(values["KNOT_SOURCE_GROUP"])),
		UserWorkspace:      strings.TrimSpace(values["KNOT_USER_WORKSPACE"]),
		GroupWorkspace:     strings.TrimSpace(values["KNOT_GROUP_WORKSPACE"]),
		CodexSessionID:     strings.TrimSpace(values["KNOT_CODEX_SESSION_ID"]),
	}
	if !ctx.validEnvBinding() {
		return nil
	}
	return ctx
}

func VerifyKnotOutboundAttachmentPathFromEnv(path string, env []string) (string, error) {
	if !knotOutboundAttachmentPolicyRequired(env) {
		return "", nil
	}
	ctx := knotAuditContextFromEnv(env)
	if ctx == nil {
		return "unauthorized_group", errors.New("invalid Knot attachment context")
	}
	if reason, err := ctx.verifyOutboundAttachmentPath(path); err != nil {
		return reason, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "invalid_resource", err
	}
	if !info.IsDir() && fileHasMultipleLinks(info) {
		return "hardlink_denied", errors.New("attachment hardlink denied")
	}
	return "", nil
}

func EmitKnotDeliveryFailedFromEnv(reasonCode, resourceKind, resourcePath string, env []string) bool {
	ctx := knotAuditContextFromEnv(env)
	if ctx == nil {
		return false
	}
	ctx.emitDeliveryFailed(reasonCode, knotAuditResource{Kind: resourceKind, Path: resourcePath})
	return true
}

func knotOutboundAttachmentPolicyRequired(env []string) bool {
	for _, entry := range env {
		if strings.HasPrefix(entry, "KNOT_SCOPE=") && strings.TrimSpace(strings.TrimPrefix(entry, "KNOT_SCOPE=")) != "" {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (ctx *knotAuditContext) withCodexSessionID(id string) *knotAuditContext {
	if ctx == nil || id == "" || ctx.CodexSessionID != "" {
		return ctx
	}
	cp := *ctx
	cp.CodexSessionID = id
	return &cp
}

func (ctx *knotAuditContext) emit(event, status, reasonCode string, resource knotAuditResource) {
	if ctx == nil || strings.TrimSpace(ctx.ConversationDir) == "" {
		return
	}
	row := knotAuditEvent{
		SchemaVersion:      "0.1",
		Time:               time.Now().UTC().Format(time.RFC3339),
		Event:              event,
		Platform:           ctx.Platform,
		ChatIDHash:         ctx.ChatIDHash,
		PlatformUserIDHash: ctx.PlatformUserIDHash,
		IdentityKeyHash:    ctx.IdentityKeyHash,
		ActorUser:          ctx.ActorUser,
		GroupSlug:          ctx.GroupSlug,
		CodexSessionID:     ctx.CodexSessionID,
		Status:             status,
		ReasonCode:         reasonCode,
		ResourceKind:       resource.Kind,
	}
	if resource.Path != "" {
		row.ResourcePath = ctx.relativePath(resource.Path)
		if stat, err := os.Stat(resource.Path); err == nil && !stat.IsDir() {
			row.ResourceSizeBytes = stat.Size()
			if data, err := os.ReadFile(resource.Path); err == nil {
				sum := sha256.Sum256(data)
				row.ResourceSHA256 = hex.EncodeToString(sum[:])
			}
		}
	} else if len(resource.Data) > 0 {
		row.ResourceSizeBytes = int64(len(resource.Data))
		sum := sha256.Sum256(resource.Data)
		row.ResourceSHA256 = hex.EncodeToString(sum[:])
	}

	data, err := json.Marshal(row)
	if err != nil {
		slog.Warn("knot audit marshal failed", "event", event, "error", err)
		return
	}
	if err := os.MkdirAll(ctx.ConversationDir, 0o755); err != nil {
		slog.Warn("knot audit mkdir failed", "event", event, "error", err)
		return
	}
	path := filepath.Join(ctx.ConversationDir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		slog.Warn("knot audit open failed", "event", event, "error", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		slog.Warn("knot audit write failed", "event", event, "error", err)
	}
}

func (ctx *knotAuditContext) emitDeliveryFailed(reasonCode string, resource knotAuditResource) {
	ctx.emit("delivery.failed", "failed", reasonCode, resource)
}

func (ctx *knotAuditContext) emitDeliverySent(resource knotAuditResource) {
	ctx.emit("delivery.sent", "sent", "", resource)
}

func (ctx *knotAuditContext) validEnvBinding() bool {
	if ctx == nil || ctx.Root == "" || ctx.ConversationDir == "" || ctx.Platform == "" ||
		!validSHA256Hash(ctx.ChatIDHash) || !validSHA256Hash(ctx.PlatformUserIDHash) {
		return false
	}
	if ctx.IdentityKeyHash != "" && !validSHA256Hash(ctx.IdentityKeyHash) {
		return false
	}
	if ctx.Scope != "" && ctx.Scope != "direct" && ctx.Scope != "group" {
		return false
	}
	root, err := filepath.Abs(ctx.Root)
	if err != nil {
		return false
	}
	conversationDir, err := filepath.Abs(ctx.ConversationDir)
	if err != nil {
		return false
	}
	hash := strings.TrimPrefix(ctx.ChatIDHash, "sha256:")
	expected := filepath.Join(root, "workspace", "conversations", ctx.Platform, "chat_"+hash[:24])
	if conversationDir != expected {
		return false
	}
	for _, path := range []string{
		root,
		filepath.Join(root, "workspace"),
		filepath.Join(root, "workspace", "conversations"),
		filepath.Join(root, "workspace", "conversations", ctx.Platform),
		conversationDir,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

func validSHA256Hash(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "sha256:") {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (ctx *knotAuditContext) relativePath(path string) string {
	if ctx == nil || ctx.Root == "" {
		return path
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	absRoot, err := filepath.Abs(ctx.Root)
	if err != nil {
		return path
	}
	if rel, err := filepath.Rel(absRoot, absPath); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
		return rel
	}
	return path
}
