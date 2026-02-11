package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHashAPIKey_SHA256(t *testing.T) {
	key := "sk-test-key-12345"
	got := hashAPIKey(key)

	// Verify it's a valid hex-encoded SHA256.
	expected := sha256.Sum256([]byte(key))
	want := hex.EncodeToString(expected[:])

	if got != want {
		t.Errorf("hashAPIKey(%q) = %q, want SHA256 %q", key, got, want)
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	key := "sk-my-api-key"
	h1 := hashAPIKey(key)
	h2 := hashAPIKey(key)
	if h1 != h2 {
		t.Error("hashAPIKey should be deterministic")
	}
}

func TestHashAPIKey_DifferentKeys(t *testing.T) {
	h1 := hashAPIKey("key-one")
	h2 := hashAPIKey("key-two")
	if h1 == h2 {
		t.Error("different keys should produce different hashes")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if len(key) < 10 {
		t.Errorf("key too short: %q", key)
	}
	if key[:3] != "sk-" {
		t.Errorf("expected sk- prefix, got %q", key[:3])
	}

	// Unique keys.
	key2, _ := GenerateAPIKey()
	if key == key2 {
		t.Error("expected unique API keys")
	}
}
