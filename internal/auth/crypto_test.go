package auth

import (
	"strings"
	"testing"
)

const testMasterKey = "test-master-key-that-is-32bytes!"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	const plaintext = "my-secret-access-key-value"
	ciphertext, err := EncryptSecret(testMasterKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}

	decrypted, err := DecryptSecret(testMasterKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptSecret_DifferentCiphertextPerCall(t *testing.T) {
	// Same plaintext must produce different ciphertexts due to random nonce.
	const plaintext = "same-secret-value"
	c1, err := EncryptSecret(testMasterKey, plaintext)
	if err != nil {
		t.Fatalf("first EncryptSecret: %v", err)
	}
	c2, err := EncryptSecret(testMasterKey, plaintext)
	if err != nil {
		t.Fatalf("second EncryptSecret: %v", err)
	}
	if c1 == c2 {
		t.Error("two encryptions of the same plaintext must differ (random nonce)")
	}
	// Both must still decrypt to the same plaintext.
	d1, _ := DecryptSecret(testMasterKey, c1)
	d2, _ := DecryptSecret(testMasterKey, c2)
	if d1 != plaintext || d2 != plaintext {
		t.Errorf("both ciphertexts must decrypt to %q, got %q and %q", plaintext, d1, d2)
	}
}

func TestEncryptSecret_HasVersionPrefix(t *testing.T) {
	ciphertext, err := EncryptSecret(testMasterKey, "secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if !strings.HasPrefix(ciphertext, "v1:") {
		t.Errorf("expected ciphertext to start with version prefix 'v1:', got %q", ciphertext)
	}
}

func TestDecryptSecret_WrongKey(t *testing.T) {
	// Decryption with wrong key must fail (GCM authentication tag mismatch).
	ciphertext, err := EncryptSecret(testMasterKey, "secret-value")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}

	wrongKey := "wrong-master-key-that-is-32byt!"
	_, err = DecryptSecret(wrongKey, ciphertext)
	if err == nil {
		t.Error("expected decryption with wrong key to fail, got nil error")
	}
}

func TestDecryptSecret_InvalidFormat_NoParts(t *testing.T) {
	_, err := DecryptSecret(testMasterKey, "not-a-valid-format")
	if err == nil {
		t.Error("expected error for ciphertext with wrong number of parts")
	}
}

func TestDecryptSecret_UnsupportedVersion(t *testing.T) {
	_, err := DecryptSecret(testMasterKey, "v99:abc:def")
	if err == nil {
		t.Error("expected error for unsupported ciphertext version")
	}
}

func TestDecryptSecret_TamperedCiphertext(t *testing.T) {
	// Modify the ciphertext bytes; GCM authentication must reject it.
	ciphertext, err := EncryptSecret(testMasterKey, "important-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	// Flip the last character of the ciphertext.
	parts := strings.SplitN(ciphertext, ":", 3)
	ct := []byte(parts[2])
	ct[len(ct)-1] ^= 0x01
	tampered := parts[0] + ":" + parts[1] + ":" + string(ct)

	_, err = DecryptSecret(testMasterKey, tampered)
	if err == nil {
		t.Error("expected authentication failure for tampered ciphertext")
	}
}

func TestEncryptSecret_EmptyPlaintext(t *testing.T) {
	// Encrypting empty string should succeed and round-trip cleanly.
	ciphertext, err := EncryptSecret(testMasterKey, "")
	if err != nil {
		t.Fatalf("EncryptSecret of empty string: %v", err)
	}
	decrypted, err := DecryptSecret(testMasterKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptSecret of empty ciphertext: %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string after round-trip, got %q", decrypted)
	}
}

func TestGenerateAccessKeyID_Format(t *testing.T) {
	keyID, err := GenerateAccessKeyID()
	if err != nil {
		t.Fatalf("GenerateAccessKeyID: %v", err)
	}

	// Must be 20 characters (AKIA + 16).
	if len(keyID) != 20 {
		t.Errorf("expected length 20, got %d", len(keyID))
	}

	// Must start with AKIA.
	if !strings.HasPrefix(keyID, "AKIA") {
		t.Errorf("expected prefix 'AKIA', got %q", keyID[:4])
	}

	// All characters after AKIA must be uppercase alphanumeric.
	suffix := keyID[4:]
	for _, c := range suffix {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			t.Errorf("invalid character %q in suffix %q", c, suffix)
		}
	}
}

func TestGenerateAccessKeyID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		keyID, err := GenerateAccessKeyID()
		if err != nil {
			t.Fatalf("GenerateAccessKeyID: %v", err)
		}
		if ids[keyID] {
			t.Fatalf("duplicate key ID generated: %s", keyID)
		}
		ids[keyID] = true
	}
}

func TestGenerateSecretAccessKey_Format(t *testing.T) {
	secret, err := GenerateSecretAccessKey()
	if err != nil {
		t.Fatalf("GenerateSecretAccessKey: %v", err)
	}

	// Must be 40 characters (30 bytes → 40 base64 chars).
	if len(secret) != 40 {
		t.Errorf("expected length 40, got %d", len(secret))
	}

	// Must be valid base64url characters.
	for _, c := range secret {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=') {
			t.Errorf("invalid base64url character %q in secret", c)
		}
	}
}

func TestGenerateSecretAccessKey_Uniqueness(t *testing.T) {
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := GenerateSecretAccessKey()
		if err != nil {
			t.Fatalf("GenerateSecretAccessKey: %v", err)
		}
		if secrets[secret] {
			t.Fatalf("duplicate secret generated")
		}
		secrets[secret] = true
	}
}
