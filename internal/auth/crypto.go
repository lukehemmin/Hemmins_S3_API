package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// ciphertextVersion identifies the encryption scheme used.
// Allows future key-rotation or algorithm migration without breaking existing records.
const ciphertextVersion = "v1"

// EncryptSecret encrypts plaintext using AES-256-GCM with a key derived from masterKey.
// Returns a versioned encoded string: "v1:<nonce_b64>:<ciphertext_b64>".
// Each call produces a different ciphertext because a fresh random nonce is used.
// Per security-model.md section 4.2: access key secrets must be encrypted with auth.master_key.
func EncryptSecret(masterKey, plaintext string) (string, error) {
	key := deriveAESKey(masterKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	ciphertextB64 := base64.RawStdEncoding.EncodeToString(ciphertext)

	return fmt.Sprintf("%s:%s:%s", ciphertextVersion, nonceB64, ciphertextB64), nil
}

// DecryptSecret decrypts a ciphertext produced by EncryptSecret.
// Returns the original plaintext, or an error if decryption or authentication fails.
// Per security-model.md section 4.2.
func DecryptSecret(masterKey, encoded string) (string, error) {
	parts := strings.SplitN(encoded, ":", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid ciphertext format: expected version:nonce:ciphertext, got %d parts", len(parts))
	}

	version, nonceB64, ciphertextB64 := parts[0], parts[1], parts[2]
	if version != ciphertextVersion {
		return "", fmt.Errorf("unsupported ciphertext version: %q (want %q)", version, ciphertextVersion)
	}

	key := deriveAESKey(masterKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("decoding nonce: %w", err)
	}

	ciphertext, err := base64.RawStdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decoding ciphertext: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting (authentication failed or wrong key): %w", err)
	}

	return string(plaintext), nil
}

// deriveAESKey derives a 32-byte AES-256 key from masterKey using SHA-256 with a
// domain separator. This ensures a consistent 32-byte key regardless of the
// master_key length, while keeping domain separation from any other key uses.
func deriveAESKey(masterKey string) []byte {
	h := sha256.New()
	h.Write([]byte("hemmins-s3-aes256-key-v1:"))
	h.Write([]byte(masterKey))
	return h.Sum(nil)
}

// GenerateAccessKeyID generates a new access key ID in AWS-compatible format.
// Format: "AKIA" prefix + 16 random uppercase alphanumeric characters = 20 characters total.
// The AKIA prefix indicates a long-term access key.
// This matches the AWS access key ID format for compatibility with S3 clients.
func GenerateAccessKeyID() (string, error) {
	const (
		prefix     = "AKIA"
		suffixLen  = 16
		charset    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		charsetLen = byte(len(charset))
	)

	b := make([]byte, suffixLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating access key ID: %w", err)
	}

	for i := range b {
		b[i] = charset[b[i]%charsetLen]
	}

	return prefix + string(b), nil
}

// GenerateSecretAccessKey generates a new secret access key.
// Format: 40 characters of URL-safe base64-encoded random bytes.
// This matches the typical AWS secret access key format.
func GenerateSecretAccessKey() (string, error) {
	const secretBytes = 30 // 30 bytes → 40 base64 chars

	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating secret access key: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
