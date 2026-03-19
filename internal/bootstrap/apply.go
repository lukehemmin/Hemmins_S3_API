// Package bootstrap implements the headless bootstrap flow for first-time setup.
// Per security-model.md section 3.2 and configuration-model.md section 6.
package bootstrap

import (
	"errors"
	"fmt"
	"log"

	"github.com/lukehemmin/hemmins-s3-api/internal/auth"
	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

// ErrPartialInit is returned by Apply when the database is in a partial
// initialization state (some credential records exist but bootstrap is incomplete).
// This is an inconsistent state that requires operator intervention.
// Bootstrap input must NOT be consumed in this state.
// Per security-model.md section 3.1 and configuration-model.md section 2.2.
var ErrPartialInit = errors.New(
	"database is in partial initialization state: some credential records exist " +
		"but bootstrap is incomplete; operator intervention is required",
)

// Apply applies headless bootstrap credentials to an empty metadata database.
//
// Behaviour (based on db.BootstrapState()):
//   - DBStateBootstrapped: Apply returns nil immediately; caller logs a warning.
//   - DBStatePartial: Apply returns ErrPartialInit; bootstrap must NOT run.
//     This state indicates an inconsistency requiring operator intervention.
//   - DBStateEmpty: Apply creates the admin user and root access key atomically.
//
// Per security-model.md section 3.1 and configuration-model.md section 2.2:
// bootstrap input is consumed ONLY when the DB is in the empty state.
//
// Security contracts (per security-model.md sections 4.1 and 4.2):
//   - AdminPassword is hashed with argon2id; plaintext is never stored.
//   - RootSecretKey is encrypted with AES-256-GCM using masterKey; plaintext is never stored.
//   - The bootstrap operation is atomic: either both records are created or neither.
func Apply(db *metadata.DB, bootstrapCfg *config.BootstrapConfig, masterKey string) error {
	state, err := db.BootstrapState()
	if err != nil {
		return fmt.Errorf("checking bootstrap state: %w", err)
	}

	switch state {
	case metadata.DBStateBootstrapped:
		// Already done; caller is responsible for any warning log.
		return nil
	case metadata.DBStatePartial:
		// Per security-model.md 3.1: only empty DB allows bootstrap.
		// Partial state must not be silently "fixed" by overwriting records.
		return ErrPartialInit
	case metadata.DBStateEmpty:
		// Proceed.
	}

	// Hash admin password — plaintext storage prohibited per security-model.md 4.1.
	passwordHash, err := auth.HashPassword(bootstrapCfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("hashing admin password: %w", err)
	}

	// Encrypt root secret key with master_key — per security-model.md 4.2.
	secretCiphertext, err := auth.EncryptSecret(masterKey, bootstrapCfg.RootSecretKey)
	if err != nil {
		return fmt.Errorf("encrypting root secret key: %w", err)
	}

	// Write both records atomically.
	if err := db.Bootstrap(
		bootstrapCfg.AdminUsername,
		passwordHash,
		bootstrapCfg.RootAccessKey,
		secretCiphertext,
	); err != nil {
		return fmt.Errorf("writing bootstrap records: %w", err)
	}

	log.Printf("bootstrap: completed (admin=%q, access_key=%q)", bootstrapCfg.AdminUsername, bootstrapCfg.RootAccessKey)
	return nil
}
