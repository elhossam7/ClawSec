package skills

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// FileIntegritySkill computes file hashes, checks metadata, and compares baselines.
type FileIntegritySkill struct {
	logger zerolog.Logger
}

// NewFileIntegritySkill creates a file integrity check skill.
func NewFileIntegritySkill(logger zerolog.Logger) *FileIntegritySkill {
	return &FileIntegritySkill{
		logger: logger.With().Str("skill", "file_integrity_check").Logger(),
	}
}

func (f *FileIntegritySkill) Name() string { return "file_integrity_check" }
func (f *FileIntegritySkill) Description() string {
	return "Compute file hashes (MD5/SHA1/SHA256) and check file metadata. Can scan a single file or a directory. Use when verifying binary integrity or investigating potentially tampered files."
}

func (f *FileIntegritySkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{
				"type":        "string",
				"description": "File or directory path to check",
			},
			"mode": map[string]interface{}{
				"type":        "string",
				"description": "Operation mode: 'hash' (single file) or 'scan' (directory). Default: hash",
				"enum":        []string{"hash", "scan"},
			},
			"expected_hash": map[string]interface{}{
				"type":        "string",
				"description": "Optional: expected SHA256 hash to compare against",
			},
		},
		"required": []string{"path"},
	}
}

func (f *FileIntegritySkill) Validate(params map[string]interface{}) error {
	path, err := GetStringParam(params, "path")
	if err != nil {
		return err
	}
	// Block path traversal and shell injection.
	if strings.ContainsAny(path, ";|&$`\"'") {
		return fmt.Errorf("invalid characters in path")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}
	if len(path) > 500 {
		return fmt.Errorf("path too long")
	}
	return nil
}

func (f *FileIntegritySkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	path, _ := GetStringParam(params, "path")
	mode := "hash"
	if m, err := GetStringParam(params, "mode"); err == nil && m != "" {
		mode = m
	}
	expectedHash := ""
	if eh, err := GetStringParam(params, "expected_hash"); err == nil {
		expectedHash = eh
	}

	f.logger.Info().Str("path", path).Str("mode", mode).Msg("file integrity check")

	switch mode {
	case "hash":
		return f.hashFile(path, expectedHash)
	case "scan":
		return f.scanDirectory(ctx, path)
	default:
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("unknown mode: %s", mode)}, nil
	}
}

func (f *FileIntegritySkill) hashFile(path, expectedHash string) (*types.ToolResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("stat failed: %v", err)}, nil
	}
	if info.IsDir() {
		return &types.ToolResult{Success: false, Error: "path is a directory, use mode=scan"}, nil
	}
	// Limit file size to 100MB.
	if info.Size() > 100*1024*1024 {
		return &types.ToolResult{Success: false, Error: "file too large (max 100MB)"}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("open failed: %v", err)}, nil
	}
	defer file.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	writer := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	if _, err := io.Copy(writer, file); err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("read failed: %v", err)}, nil
	}

	md5Hex := fmt.Sprintf("%x", md5Hash.Sum(nil))
	sha1Hex := fmt.Sprintf("%x", sha1Hash.Sum(nil))
	sha256Hex := fmt.Sprintf("%x", sha256Hash.Sum(nil))

	var output strings.Builder
	output.WriteString(fmt.Sprintf("File Integrity Check: %s\n", path))
	output.WriteString(strings.Repeat("-", 50) + "\n")
	output.WriteString(fmt.Sprintf("Size:     %d bytes\n", info.Size()))
	output.WriteString(fmt.Sprintf("Modified: %s\n", info.ModTime().Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("Mode:     %s\n", info.Mode()))
	output.WriteString(fmt.Sprintf("MD5:      %s\n", md5Hex))
	output.WriteString(fmt.Sprintf("SHA1:     %s\n", sha1Hex))
	output.WriteString(fmt.Sprintf("SHA256:   %s\n", sha256Hex))

	hashMatch := ""
	if expectedHash != "" {
		expected := strings.ToLower(expectedHash)
		if expected == sha256Hex {
			hashMatch = "MATCH"
			output.WriteString("\nHash verification: MATCH\n")
		} else {
			hashMatch = "MISMATCH"
			output.WriteString(fmt.Sprintf("\nHash verification: MISMATCH\n  Expected: %s\n  Got:      %s\n", expected, sha256Hex))
		}
	}

	return &types.ToolResult{
		Success: true,
		Output:  output.String(),
		Data: map[string]interface{}{
			"path":       path,
			"size":       info.Size(),
			"modified":   info.ModTime().Format(time.RFC3339),
			"md5":        md5Hex,
			"sha1":       sha1Hex,
			"sha256":     sha256Hex,
			"hash_match": hashMatch,
		},
	}, nil
}

func (f *FileIntegritySkill) scanDirectory(ctx context.Context, dirPath string) (*types.ToolResult, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("stat failed: %v", err)}, nil
	}
	if !info.IsDir() {
		return &types.ToolResult{Success: false, Error: "path is not a directory, use mode=hash"}, nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Directory Scan: %s\n", dirPath))
	output.WriteString(strings.Repeat("-", 80) + "\n")
	output.WriteString(fmt.Sprintf("%-50s %-12s %s\n", "File", "Size", "SHA256"))
	output.WriteString(strings.Repeat("-", 80) + "\n")

	count := 0
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors.
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			return nil
		}
		if count >= 100 {
			return filepath.SkipAll
		}
		// Skip very large files.
		if info.Size() > 50*1024*1024 {
			output.WriteString(fmt.Sprintf("%-50s %-12s %s\n", truncatePath(path, 50), formatSize(info.Size()), "(skipped: too large)"))
			return nil
		}

		hash, err := hashFileSHA256(path)
		if err != nil {
			output.WriteString(fmt.Sprintf("%-50s %-12s %s\n", truncatePath(path, 50), formatSize(info.Size()), "(error)"))
			return nil
		}
		output.WriteString(fmt.Sprintf("%-50s %-12s %s\n", truncatePath(path, 50), formatSize(info.Size()), hash[:16]+"..."))
		count++
		return nil
	})

	output.WriteString(fmt.Sprintf("\nScanned %d files\n", count))

	return &types.ToolResult{
		Success: true,
		Output:  output.String(),
		Data: map[string]interface{}{
			"directory":     dirPath,
			"files_scanned": count,
		},
	}, nil
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}

func formatSize(size int64) string {
	switch {
	case size >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(size)/(1024*1024*1024))
	case size >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	case size >= 1024:
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	default:
		return fmt.Sprintf("%d B", size)
	}
}
