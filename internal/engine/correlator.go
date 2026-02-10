package engine

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Correlator tracks event counts per rule/key within sliding time windows.
// It enables threshold-based detection like "5 failed logins in 5 minutes from the same IP."
type Correlator struct {
	buckets map[string]*correlationBucket
	mu      sync.Mutex
	logger  zerolog.Logger
}

type correlationBucket struct {
	entries []time.Time
	window  time.Duration
}

// NewCorrelator creates a new correlator.
func NewCorrelator(logger zerolog.Logger) *Correlator {
	return &Correlator{
		buckets: make(map[string]*correlationBucket),
		logger:  logger.With().Str("component", "correlator").Logger(),
	}
}

// Increment adds an occurrence and returns the current count within the window.
func (c *Correlator) Increment(ruleID, key string, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	bucketKey := ruleID + ":" + key
	bucket, ok := c.buckets[bucketKey]
	if !ok {
		bucket = &correlationBucket{window: window}
		c.buckets[bucketKey] = bucket
	}

	now := time.Now()
	bucket.entries = append(bucket.entries, now)

	// Remove expired entries.
	cutoff := now.Add(-window)
	valid := bucket.entries[:0]
	for _, t := range bucket.entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	bucket.entries = valid

	return len(bucket.entries)
}

// Reset clears the count for a rule/key combination.
func (c *Correlator) Reset(ruleID, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.buckets, ruleID+":"+key)
}

// Start runs a periodic cleanup of expired correlation entries.
func (c *Correlator) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes expired buckets.
func (c *Correlator) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, bucket := range c.buckets {
		cutoff := now.Add(-bucket.window)
		valid := bucket.entries[:0]
		for _, t := range bucket.entries {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		bucket.entries = valid
		if len(bucket.entries) == 0 {
			delete(c.buckets, key)
		}
	}
}
