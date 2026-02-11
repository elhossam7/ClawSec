// Package logging provides log rotation and request tracing for Sentinel.
package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RotatingWriter is an io.Writer that automatically rotates log files
// when they exceed a configured size limit. It keeps a specified number
// of old log files as backups.
type RotatingWriter struct {
	path       string
	maxSizeMB  int
	maxBackups int
	file       *os.File
	size       int64
	mu         sync.Mutex
}

// NewRotatingWriter creates a log writer that rotates at maxSizeMB.
// It keeps up to maxBackups old files (e.g., sentinel.log.1, sentinel.log.2).
func NewRotatingWriter(path string, maxSizeMB, maxBackups int) (*RotatingWriter, error) {
	if maxSizeMB < 1 {
		maxSizeMB = 50
	}
	if maxBackups < 1 {
		maxBackups = 5
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}

	rw := &RotatingWriter{
		path:       path,
		maxSizeMB:  maxSizeMB,
		maxBackups: maxBackups,
	}

	if err := rw.openFile(); err != nil {
		return nil, err
	}

	return rw, nil
}

// Write implements io.Writer.
func (rw *RotatingWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	// Check if rotation is needed.
	if rw.size+int64(len(p)) > int64(rw.maxSizeMB)*1024*1024 {
		if err := rw.rotate(); err != nil {
			// If rotation fails, keep writing to the current file.
			fmt.Fprintf(os.Stderr, "log rotation failed: %v\n", err)
		}
	}

	n, err := rw.file.Write(p)
	rw.size += int64(n)
	return n, err
}

// Close closes the underlying file.
func (rw *RotatingWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.file != nil {
		return rw.file.Close()
	}
	return nil
}

func (rw *RotatingWriter) openFile() error {
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}

	rw.file = f
	rw.size = info.Size()
	return nil
}

func (rw *RotatingWriter) rotate() error {
	// Close current file.
	if rw.file != nil {
		rw.file.Close()
	}

	// Shift existing backups: .3 → .4, .2 → .3, .1 → .2, current → .1
	for i := rw.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", rw.path, i)
		dst := fmt.Sprintf("%s.%d", rw.path, i+1)
		os.Rename(src, dst)
	}

	// Rename current to .1
	if err := os.Rename(rw.path, rw.path+".1"); err != nil && !os.IsNotExist(err) {
		// If rename fails, truncate instead.
		return rw.openFile()
	}

	// Delete oldest if over limit.
	oldest := fmt.Sprintf("%s.%d", rw.path, rw.maxBackups+1)
	os.Remove(oldest)

	// Open new file.
	return rw.openFile()
}

// RequestIDGenerator provides unique request IDs for HTTP request tracing.
type RequestIDGenerator struct {
	counter uint64
	prefix  string
	mu      sync.Mutex
}

// NewRequestIDGenerator creates a request ID generator with a unique prefix
// based on the current process start time.
func NewRequestIDGenerator() *RequestIDGenerator {
	return &RequestIDGenerator{
		prefix: fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFF),
	}
}

// Next generates the next unique request ID.
func (g *RequestIDGenerator) Next() string {
	g.mu.Lock()
	g.counter++
	id := g.counter
	g.mu.Unlock()
	return fmt.Sprintf("req-%s-%06d", g.prefix, id)
}
