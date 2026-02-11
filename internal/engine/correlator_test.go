package engine

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestCorrelator_Increment_CountsWithinWindow(t *testing.T) {
	c := NewCorrelator(zerolog.Nop())

	// Increment 5 times.
	var count int
	for i := 0; i < 5; i++ {
		count = c.Increment("rule-ssh-brute", "10.0.0.1", 5*time.Minute)
	}

	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestCorrelator_Increment_DifferentKeys(t *testing.T) {
	c := NewCorrelator(zerolog.Nop())

	c.Increment("rule-ssh-brute", "10.0.0.1", 5*time.Minute)
	c.Increment("rule-ssh-brute", "10.0.0.1", 5*time.Minute)
	count := c.Increment("rule-ssh-brute", "10.0.0.2", 5*time.Minute)

	// Different key, should be count 1.
	if count != 1 {
		t.Errorf("expected count 1 for different key, got %d", count)
	}
}

func TestCorrelator_Increment_ExpiresOldEntries(t *testing.T) {
	c := NewCorrelator(zerolog.Nop())

	// Use a very short window.
	c.Increment("rule-test", "key1", 50*time.Millisecond)
	c.Increment("rule-test", "key1", 50*time.Millisecond)

	// Wait for the window to expire.
	time.Sleep(100 * time.Millisecond)

	// After window, count should be 1 (only the new one).
	count := c.Increment("rule-test", "key1", 50*time.Millisecond)
	if count != 1 {
		t.Errorf("expected count 1 after window expiry, got %d", count)
	}
}

func TestCorrelator_Reset(t *testing.T) {
	c := NewCorrelator(zerolog.Nop())

	c.Increment("rule-test", "key1", 5*time.Minute)
	c.Increment("rule-test", "key1", 5*time.Minute)
	c.Reset("rule-test", "key1")

	// After reset, count should be 1.
	count := c.Increment("rule-test", "key1", 5*time.Minute)
	if count != 1 {
		t.Errorf("expected count 1 after reset, got %d", count)
	}
}

func TestCorrelator_Cleanup_RemovesExpiredBuckets(t *testing.T) {
	c := NewCorrelator(zerolog.Nop())

	// Add entries with very short window.
	c.Increment("rule-expiry", "key1", 50*time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	c.cleanup()

	// Bucket should be removed.
	c.mu.Lock()
	_, exists := c.buckets["rule-expiry:key1"]
	c.mu.Unlock()

	if exists {
		t.Error("expected expired bucket to be cleaned up")
	}
}
