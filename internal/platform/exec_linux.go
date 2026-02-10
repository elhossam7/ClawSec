//go:build linux

package platform

import (
	"context"
	"os/exec"
)

// execCommandContext wraps exec.CommandContext for linux.
func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
