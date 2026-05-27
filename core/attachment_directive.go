package core

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type outboundAttachmentDirective struct {
	kind string
	path string
}

type outboundAttachmentData struct {
	kind  string
	image ImageAttachment
	file  FileAttachment
}

const (
	attachmentDirectiveFence = "```cc-connect-attachments"
	attachmentFenceClose     = "```"
	attachmentKindImage      = "image"
	attachmentKindFile       = "file"
)

var (
	errAttachmentChangedDuringRead = errors.New("attachment changed during read")
	errAttachmentHardlinked        = errors.New("attachment hardlink denied")
)

var readAttachmentFile = os.ReadFile

func extractAttachmentDirectives(text string) (string, []outboundAttachmentDirective, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	cleanLines := make([]string, 0, len(lines))
	var attachments []outboundAttachmentDirective
	var block []string
	inBlock := false
	found := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inBlock {
			if trimmed == attachmentFenceClose {
				dirs, err := parseAttachmentDirectiveBlock(block)
				if err != nil {
					return text, nil, err
				}
				attachments = append(attachments, dirs...)
				block = nil
				inBlock = false
				found = true
				continue
			}
			block = append(block, line)
			continue
		}
		if trimmed == attachmentDirectiveFence {
			inBlock = true
			block = nil
			continue
		}
		cleanLines = append(cleanLines, line)
	}
	if inBlock {
		return text, nil, fmt.Errorf("unterminated cc-connect-attachments block")
	}
	if !found {
		return text, nil, nil
	}
	clean := strings.TrimSpace(strings.Join(cleanLines, "\n"))
	return collapseExtraBlankLines(clean), attachments, nil
}

func collapseExtraBlankLines(text string) string {
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	return text
}

func parseAttachmentDirectiveBlock(lines []string) ([]outboundAttachmentDirective, error) {
	var attachments []outboundAttachmentDirective
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid attachment directive line %q", line)
		}
		kind := strings.ToLower(strings.TrimSpace(key))
		switch kind {
		case attachmentKindImage, attachmentKindFile:
		default:
			return nil, fmt.Errorf("unsupported attachment directive kind %q", kind)
		}
		path := strings.Trim(strings.TrimSpace(value), `"'`)
		if path == "" {
			return nil, fmt.Errorf("empty attachment path for %s", kind)
		}
		attachments = append(attachments, outboundAttachmentDirective{kind: kind, path: path})
	}
	return attachments, nil
}

func buildAttachmentFromDirective(dir outboundAttachmentDirective) (outboundAttachmentData, error) {
	return loadAttachmentFromDirective(dir)
}

func buildAttachmentFromDirectiveWithPolicy(dir outboundAttachmentDirective, auditCtx *knotAuditContext) (outboundAttachmentData, string, error) {
	if reason, err := auditCtx.verifyOutboundAttachmentPath(dir.path); err != nil {
		return outboundAttachmentData{}, reason, err
	}
	attachment, err := loadAttachmentFromDirective(dir)
	if err != nil {
		if errors.Is(err, errAttachmentChangedDuringRead) {
			return outboundAttachmentData{}, "attachment_hash_mismatch", err
		}
		if errors.Is(err, errAttachmentHardlinked) {
			return outboundAttachmentData{}, "hardlink_denied", err
		}
		return outboundAttachmentData{}, "attachment_read_failed", err
	}
	return attachment, "", nil
}

func (ctx *knotAuditContext) verifyOutboundAttachmentPath(path string) (string, error) {
	if ctx == nil || ctx.Scope == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "outside_deliverables", fmt.Errorf("attachment path must be absolute: %s", path)
	}

	var deliverablesDir string
	switch ctx.Scope {
	case "direct":
		userWorkspace := strings.TrimSpace(ctx.UserWorkspace)
		if userWorkspace == "" {
			if ctx.Root == "" || ctx.ActorUser == "" {
				return "unauthorized_group", fmt.Errorf("direct attachment context is missing actor workspace")
			}
			userWorkspace = filepath.Join(ctx.Root, "workspace", "users", ctx.ActorUser)
		}
		deliverablesDir = filepath.Join(userWorkspace, "deliverables")
	case "group":
		groupWorkspace := strings.TrimSpace(ctx.GroupWorkspace)
		if groupWorkspace == "" {
			if ctx.Root == "" || ctx.GroupSlug == "" {
				return "unauthorized_group", fmt.Errorf("group attachment context is missing group workspace")
			}
			groupWorkspace = filepath.Join(ctx.Root, "workspace", "groups", ctx.GroupSlug)
		}
		deliverablesDir = filepath.Join(groupWorkspace, "deliverables")
	default:
		return "unauthorized_group", fmt.Errorf("unsupported Knot attachment scope: %s", ctx.Scope)
	}

	if pathContainsSymlinkUnder(ctx.Root, deliverablesDir) {
		return "symlink_denied", fmt.Errorf("attachment deliverables directory must not include symlinks: %s", deliverablesDir)
	}
	allowedRoot, err := filepath.EvalSymlinks(deliverablesDir)
	if err != nil {
		return "invalid_resource", fmt.Errorf("resolve attachment deliverables directory: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "invalid_resource", fmt.Errorf("resolve attachment path: %w", err)
	}
	if !pathIsUnder(resolvedPath, allowedRoot) {
		if pathIsUnderClean(path, deliverablesDir) && pathContainsSymlinkUnder(deliverablesDir, path) {
			return "symlink_denied", fmt.Errorf("attachment path must not include symlinks: %s", path)
		}
		return "outside_deliverables", fmt.Errorf("attachment must be inside the current Knot deliverables directory: %s", path)
	}
	if pathContainsSymlinkUnder(deliverablesDir, path) {
		return "symlink_denied", fmt.Errorf("attachment path must not include symlinks: %s", path)
	}
	return "", nil
}

func pathContainsSymlinkUnder(base, path string) bool {
	if base == "" {
		return true
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return true
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(absBase, absPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	current := absBase
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func pathIsUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathIsUnderClean(path, dir string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	return pathIsUnder(absPath, absDir)
}

func loadAttachmentFromDirective(dir outboundAttachmentDirective) (outboundAttachmentData, error) {
	if !filepath.IsAbs(dir.path) {
		return outboundAttachmentData{}, fmt.Errorf("attachment path must be absolute: %s", dir.path)
	}
	info, err := os.Stat(dir.path)
	if err != nil {
		return outboundAttachmentData{}, fmt.Errorf("stat attachment %s: %w", dir.path, err)
	}
	if info.IsDir() {
		return outboundAttachmentData{}, fmt.Errorf("attachment path is a directory: %s", dir.path)
	}
	if fileHasMultipleLinks(info) {
		return outboundAttachmentData{}, fmt.Errorf("%w: %s", errAttachmentHardlinked, dir.path)
	}
	data, err := readAttachmentFile(dir.path)
	if err != nil {
		return outboundAttachmentData{}, fmt.Errorf("read attachment %s: %w", dir.path, err)
	}
	afterInfo, err := os.Stat(dir.path)
	if err != nil {
		return outboundAttachmentData{}, fmt.Errorf("stat attachment after read %s: %w", dir.path, err)
	}
	if afterInfo.Size() != info.Size() || !afterInfo.ModTime().Equal(info.ModTime()) {
		return outboundAttachmentData{}, fmt.Errorf("%w: %s", errAttachmentChangedDuringRead, dir.path)
	}
	name := filepath.Base(dir.path)
	mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	switch dir.kind {
	case attachmentKindImage:
		if !strings.HasPrefix(mimeType, "image/") {
			return outboundAttachmentData{}, fmt.Errorf("attachment is not an image: %s", dir.path)
		}
		return outboundAttachmentData{
			kind: attachmentKindImage,
			image: ImageAttachment{
				MimeType: mimeType,
				Data:     data,
				FileName: name,
			},
		}, nil
	case attachmentKindFile:
		return outboundAttachmentData{
			kind: attachmentKindFile,
			file: FileAttachment{
				MimeType: mimeType,
				Data:     data,
				FileName: name,
			},
		}, nil
	default:
		return outboundAttachmentData{}, fmt.Errorf("unsupported attachment directive kind %q", dir.kind)
	}
}

func fileHasMultipleLinks(info os.FileInfo) bool {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return false
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return false
	}
	switch field.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() > 1
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() > 1
	default:
		return false
	}
}
