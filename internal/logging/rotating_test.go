package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// NewRotatingWriter
// ---------------------------------------------------------------------------

func TestNewRotatingWriter_CreatesDirectoryAndFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "nested", "app.log")

	rw, err := NewRotatingWriter(logPath, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatal("expected log file to be created, but it does not exist")
	}
}

func TestNewRotatingWriter_DefaultsMaxSizeMB(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 0, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if rw.maxSizeMB != 50 {
		t.Errorf("expected maxSizeMB default 50, got %d", rw.maxSizeMB)
	}
}

func TestNewRotatingWriter_DefaultsMaxSizeMB_Negative(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, -5, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if rw.maxSizeMB != 50 {
		t.Errorf("expected maxSizeMB default 50, got %d", rw.maxSizeMB)
	}
}

func TestNewRotatingWriter_DefaultsMaxBackups(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 10, 0)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if rw.maxBackups != 5 {
		t.Errorf("expected maxBackups default 5, got %d", rw.maxBackups)
	}
}

func TestNewRotatingWriter_DefaultsMaxBackups_Negative(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 10, -2)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if rw.maxBackups != 5 {
		t.Errorf("expected maxBackups default 5, got %d", rw.maxBackups)
	}
}

func TestNewRotatingWriter_ExplicitValues(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 25, 7)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if rw.maxSizeMB != 25 {
		t.Errorf("expected maxSizeMB 25, got %d", rw.maxSizeMB)
	}
	if rw.maxBackups != 7 {
		t.Errorf("expected maxBackups 7, got %d", rw.maxBackups)
	}
}

func TestNewRotatingWriter_AppendsToExistingFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	// Pre-create the file with some content.
	if err := os.WriteFile(logPath, []byte("existing content\n"), 0640); err != nil {
		t.Fatalf("failed to pre-create log file: %v", err)
	}

	rw, err := NewRotatingWriter(logPath, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}

	if _, err := rw.Write([]byte("new line\n")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	rw.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}

	if !strings.Contains(string(data), "existing content") {
		t.Error("expected file to contain pre-existing content (append mode)")
	}
	if !strings.Contains(string(data), "new line") {
		t.Error("expected file to contain newly written content")
	}
}

func TestNewRotatingWriter_TracksSizeOfExistingFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	seed := []byte("0123456789") // 10 bytes
	if err := os.WriteFile(logPath, seed, 0640); err != nil {
		t.Fatalf("failed to seed log file: %v", err)
	}

	rw, err := NewRotatingWriter(logPath, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	if rw.size != int64(len(seed)) {
		t.Errorf("expected initial size %d, got %d", len(seed), rw.size)
	}
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

func TestWrite_WritesDataAndTracksSize(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	msg := []byte("hello world\n")
	n, err := rw.Write(msg)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
	if rw.size != int64(len(msg)) {
		t.Errorf("expected tracked size %d, got %d", len(msg), rw.size)
	}
}

func TestWrite_MultipleWrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	line := []byte("log line\n")
	total := 0
	for i := 0; i < 10; i++ {
		n, err := rw.Write(line)
		if err != nil {
			t.Fatalf("Write #%d returned error: %v", i, err)
		}
		total += n
	}

	if rw.size != int64(total) {
		t.Errorf("expected size %d after 10 writes, got %d", total, rw.size)
	}
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestClose_ClosesFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}

	if err := rw.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// After close, writing to the underlying file should fail or the file
	// handle should be invalid. We simply verify Close did not panic.
}

func TestClose_NilFileIsNoOp(t *testing.T) {
	rw := &RotatingWriter{}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close on nil file returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Rotation logic
// ---------------------------------------------------------------------------

// writeChunk is a helper that builds a byte slice of a specific size.
func writeChunk(size int) []byte {
	chunk := make([]byte, size)
	for i := range chunk {
		chunk[i] = 'A'
	}
	return chunk
}

func TestRotation_TriggeredWhenSizeExceeded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	// Use 1 MB max size so rotation triggers quickly.
	rw, err := NewRotatingWriter(logPath, 1, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	// Write slightly more than 1 MB to trigger rotation.
	chunkSize := 256 * 1024 // 256 KB per write
	for i := 0; i < 5; i++ {
		if _, err := rw.Write(writeChunk(chunkSize)); err != nil {
			t.Fatalf("Write #%d returned error: %v", i, err)
		}
	}

	// After rotation, backup .1 should exist.
	backup1 := logPath + ".1"
	if _, err := os.Stat(backup1); os.IsNotExist(err) {
		t.Errorf("expected backup file %s to exist after rotation", backup1)
	}

	// Current file should still exist and be smaller than maxSizeMB.
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("current log file missing after rotation: %v", err)
	}
	if info.Size() > 1*1024*1024 {
		t.Errorf("expected current file smaller than 1 MB after rotation, got %d bytes", info.Size())
	}
}

func TestRotation_ShiftsBackups(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	// maxBackups = 3 -> keeps .1, .2, .3
	rw, err := NewRotatingWriter(logPath, 1, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	// Trigger multiple rotations by writing > 1 MB repeatedly.
	oneMB := 1024*1024 + 1
	for i := 0; i < 4; i++ {
		if _, err := rw.Write(writeChunk(oneMB)); err != nil {
			t.Fatalf("Write round %d returned error: %v", i, err)
		}
	}

	// We expect .1, .2, .3 to exist.
	for i := 1; i <= 3; i++ {
		backup := fmt.Sprintf("%s.%d", logPath, i)
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			t.Errorf("expected backup %s to exist", backup)
		}
	}
}

func TestRotation_DeletesOldestBeyondMax(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	// maxBackups = 2 -> keeps .1, .2 only. .3 should be deleted.
	rw, err := NewRotatingWriter(logPath, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	oneMB := 1024*1024 + 1
	for i := 0; i < 4; i++ {
		if _, err := rw.Write(writeChunk(oneMB)); err != nil {
			t.Fatalf("Write round %d returned error: %v", i, err)
		}
	}

	// .1 and .2 should exist.
	for i := 1; i <= 2; i++ {
		backup := fmt.Sprintf("%s.%d", logPath, i)
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			t.Errorf("expected backup %s to exist", backup)
		}
	}

	// .3 should NOT exist (oldest pruned).
	pruned := fmt.Sprintf("%s.%d", logPath, 3)
	if _, err := os.Stat(pruned); !os.IsNotExist(err) {
		t.Errorf("expected backup %s to be deleted, but it exists", pruned)
	}
}

func TestRotation_OpensNewFileAfterRotate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	// Fill and rotate.
	oneMB := 1024*1024 + 1
	if _, err := rw.Write(writeChunk(oneMB)); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	// Write a marker after rotation to prove new file is usable.
	marker := []byte("POST-ROTATION-MARKER\n")
	if _, err := rw.Write(marker); err != nil {
		t.Fatalf("Write after rotation returned error: %v", err)
	}

	rw.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading current log: %v", err)
	}
	if !strings.Contains(string(data), "POST-ROTATION-MARKER") {
		t.Error("expected marker in the new log file after rotation")
	}
}

func TestRotation_SizeResetsAfterRotate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	// Exceed 1 MB to trigger rotation. The rotation happens first, then the
	// full chunk is written to the newly-opened file. So rw.size == oneMB.
	oneMB := 1024*1024 + 1
	if _, err := rw.Write(writeChunk(oneMB)); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	// Verify the backup was created (rotation happened).
	if _, err := os.Stat(logPath + ".1"); os.IsNotExist(err) {
		t.Fatal("expected backup .1 to exist after rotation")
	}

	// Write a small marker; the tracked size should be oneMB + marker.
	marker := []byte("OK\n")
	if _, err := rw.Write(marker); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	expected := int64(oneMB) + int64(len(marker))
	if rw.size != expected {
		t.Errorf("expected tracked size %d, got %d", expected, rw.size)
	}
}

// ---------------------------------------------------------------------------
// Concurrent writes
// ---------------------------------------------------------------------------

func TestWrite_ConcurrentSafety(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	rw, err := NewRotatingWriter(logPath, 1, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	var wg sync.WaitGroup
	goroutines := 10
	writesPerGoroutine := 200
	line := []byte("concurrent log line that exercises the mutex path\n")

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				if _, err := rw.Write(line); err != nil {
					t.Errorf("concurrent Write returned error: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// Verify the file (and any backups) exist and no panic occurred.
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatal("log file missing after concurrent writes")
	}
}

func TestWrite_ConcurrentWithRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	// Small maxSize to provoke frequent rotations under concurrency.
	rw, err := NewRotatingWriter(logPath, 1, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter returned error: %v", err)
	}
	defer rw.Close()

	var wg sync.WaitGroup
	goroutines := 8
	// Each goroutine writes ~512 KB total, so in aggregate we exceed 1 MB
	// many times, forcing concurrent rotation attempts.
	chunk := writeChunk(4096)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 128; i++ {
				if _, err := rw.Write(chunk); err != nil {
					t.Errorf("concurrent Write returned error: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// Primary assertion: no data races or panics (run with -race).
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatal("log file missing after concurrent rotated writes")
	}

	// At least one backup should have been created given the volume of data.
	backup1 := logPath + ".1"
	if _, err := os.Stat(backup1); os.IsNotExist(err) {
		t.Error("expected at least one backup file after heavy concurrent writes")
	}
}

// ---------------------------------------------------------------------------
// RequestIDGenerator
// ---------------------------------------------------------------------------

func TestNewRequestIDGenerator_HasPrefix(t *testing.T) {
	gen := NewRequestIDGenerator()
	if gen.prefix == "" {
		t.Fatal("expected non-empty prefix from NewRequestIDGenerator")
	}
}

func TestRequestIDGenerator_Next_Format(t *testing.T) {
	gen := NewRequestIDGenerator()
	id := gen.Next()

	if !strings.HasPrefix(id, "req-") {
		t.Errorf("expected ID to start with 'req-', got %q", id)
	}

	// Must contain the prefix and a counter portion.
	parts := strings.Split(id, "-")
	// Expected format: req-{prefix}-{counter}
	if len(parts) != 3 {
		t.Errorf("expected 3 dash-separated parts, got %d in %q", len(parts), id)
	}
}

func TestRequestIDGenerator_Next_Increments(t *testing.T) {
	gen := NewRequestIDGenerator()
	id1 := gen.Next()
	id2 := gen.Next()
	id3 := gen.Next()

	if id1 == id2 || id2 == id3 {
		t.Errorf("expected unique IDs, got %q, %q, %q", id1, id2, id3)
	}

	// Counter portion should increment: 000001, 000002, 000003.
	if !strings.HasSuffix(id1, "000001") {
		t.Errorf("expected first ID to end with 000001, got %q", id1)
	}
	if !strings.HasSuffix(id2, "000002") {
		t.Errorf("expected second ID to end with 000002, got %q", id2)
	}
	if !strings.HasSuffix(id3, "000003") {
		t.Errorf("expected third ID to end with 000003, got %q", id3)
	}
}

func TestRequestIDGenerator_Next_SharedPrefix(t *testing.T) {
	gen := NewRequestIDGenerator()
	id1 := gen.Next()
	id2 := gen.Next()

	// Both IDs from the same generator share the prefix portion.
	prefix1 := strings.TrimSuffix(id1, id1[strings.LastIndex(id1, "-"):])
	prefix2 := strings.TrimSuffix(id2, id2[strings.LastIndex(id2, "-"):])

	if prefix1 != prefix2 {
		t.Errorf("expected same prefix across calls, got %q and %q", prefix1, prefix2)
	}
}

func TestRequestIDGenerator_Next_ConcurrentSafety(t *testing.T) {
	gen := NewRequestIDGenerator()

	var mu sync.Mutex
	seen := make(map[string]bool)
	var wg sync.WaitGroup

	goroutines := 10
	idsPerGoroutine := 500

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < idsPerGoroutine; i++ {
				id := gen.Next()
				mu.Lock()
				if seen[id] {
					t.Errorf("duplicate ID detected: %s", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	expected := goroutines * idsPerGoroutine
	if len(seen) != expected {
		t.Errorf("expected %d unique IDs, got %d", expected, len(seen))
	}
}

func TestRequestIDGenerator_DifferentGeneratorsHaveDifferentPrefixes(t *testing.T) {
	// Two generators created far enough apart should have different prefixes.
	// Since the prefix uses UnixNano, consecutive calls may occasionally collide,
	// so we only verify format rather than assert difference.
	gen1 := NewRequestIDGenerator()
	gen2 := NewRequestIDGenerator()

	id1 := gen1.Next()
	id2 := gen2.Next()

	// Both should be valid format.
	if !strings.HasPrefix(id1, "req-") || !strings.HasPrefix(id2, "req-") {
		t.Errorf("expected both IDs to start with 'req-', got %q and %q", id1, id2)
	}
}
