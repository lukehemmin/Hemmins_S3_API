package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per security-model.md section 4.1.
// These values meet OWASP minimum recommendations for server-side password hashing.
const (
	argon2Memory      uint32 = 64 * 1024 // 64 MiB
	argon2Iterations  uint32 = 3
	argon2Parallelism uint8  = 1
	argon2SaltLen     int    = 16
	argon2KeyLen      uint32 = 32
)

// argon2HashFormat is the encoded hash format.
// $argon2id$v=<version>$m=<memory>,t=<iterations>,p=<parallelism>$<salt_b64>$<hash_b64>
const argon2HashFormat = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"

// HashPassword hashes plaintext using argon2id and returns an encoded hash string.
// The format is compatible with the PHC string format for future interoperability.
// Per security-model.md section 4.1: plaintext storage is prohibited.
// The returned hash can be verified with VerifyPassword.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating password salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(argon2HashFormat,
		argon2.Version, argon2Memory, argon2Iterations, argon2Parallelism, saltB64, hashB64,
	), nil
}

// VerifyPassword checks whether plaintext matches the stored argon2id hash.
// Returns (true, nil) on match, (false, nil) on mismatch, and (false, err) on
// parse errors. Uses constant-time comparison to prevent timing attacks.
// Per security-model.md section 4.1.
func VerifyPassword(password, encodedHash string) (bool, error) {
	memory, iterations, parallelism, keyLen, salt, storedHash, err := parseArgon2Hash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("parsing stored hash: %w", err)
	}

	newHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
	if subtle.ConstantTimeCompare(storedHash, newHash) == 1 {
		return true, nil
	}
	return false, nil
}

// parseArgon2Hash parses an argon2id encoded hash string into its components.
// Expected format: $argon2id$v=<N>$m=<M>,t=<T>,p=<P>$<salt_b64>$<hash_b64>
func parseArgon2Hash(encodedHash string) (memory, iterations uint32, parallelism uint8, keyLen uint32, salt, hash []byte, err error) {
	// Split on "$" — first element will be empty string before leading "$"
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		err = fmt.Errorf("unsupported hash format (expected $argon2id$...)")
		return
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil {
		err = fmt.Errorf("parsing hash version: %w", scanErr)
		return
	}
	if version != argon2.Version {
		err = fmt.Errorf("unsupported argon2 version: %d (want %d)", version, argon2.Version)
		return
	}

	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); scanErr != nil {
		err = fmt.Errorf("parsing hash parameters: %w", scanErr)
		return
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		err = fmt.Errorf("decoding salt: %w", err)
		return
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		err = fmt.Errorf("decoding hash: %w", err)
		return
	}
	keyLen = uint32(len(hash))
	return
}
