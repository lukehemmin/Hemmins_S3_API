package auth

import (
	"strings"
	"testing"
)

func TestHashPassword_DifferentFromPlaintext(t *testing.T) {
	hash, err := HashPassword("my-plaintext-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "my-plaintext-password" {
		t.Error("hash must differ from plaintext")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected argon2id prefix in hash, got: %q", hash)
	}
}

func TestHashPassword_VerifySucceeds(t *testing.T) {
	const password = "correct-horse-battery-staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("expected VerifyPassword to return true for correct password")
	}
}

func TestHashPassword_VerifyFails_WrongPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("expected VerifyPassword to return false for wrong password")
	}
}

func TestHashPassword_DifferentSaltsPerCall(t *testing.T) {
	// Same password must produce different hashes due to random salt.
	// Per security-model.md 4.1: hash must be non-deterministic.
	const password = "same-password-each-time"
	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("first HashPassword: %v", err)
	}
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("second HashPassword: %v", err)
	}
	if hash1 == hash2 {
		t.Error("two hashes of the same password must differ (random salt)")
	}
	// Both must still verify correctly.
	ok1, _ := VerifyPassword(password, hash1)
	ok2, _ := VerifyPassword(password, hash2)
	if !ok1 || !ok2 {
		t.Error("both hashes must verify correctly despite differing salts")
	}
}

func TestVerifyPassword_InvalidHashFormat(t *testing.T) {
	_, err := VerifyPassword("password", "not-a-valid-hash")
	if err == nil {
		t.Error("expected error for invalid hash format, got nil")
	}
}

func TestVerifyPassword_WrongAlgorithmPrefix(t *testing.T) {
	_, err := VerifyPassword("password", "$bcrypt$some$hash")
	if err == nil {
		t.Error("expected error for unsupported algorithm prefix")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	// Empty passwords are allowed (length enforcement is the caller's job).
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword of empty string: %v", err)
	}
	ok, err := VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("VerifyPassword of empty string: %v", err)
	}
	if !ok {
		t.Error("expected VerifyPassword to return true for empty password")
	}
}
