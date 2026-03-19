package metadata

// currentSchemaVersion is the target schema version this binary expects.
// Increment this constant when adding new migrations.
const currentSchemaVersion = 1

// createSchemaVersionTable is idempotent and must run before any migration check.
const createSchemaVersionTable = `
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER NOT NULL,
    applied_at TEXT    NOT NULL
);`

// schemaV1 is the initial schema DDL.
// Per system-architecture.md sections 4.1-4.6.
const schemaV1 = `
CREATE TABLE IF NOT EXISTS buckets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_id       INTEGER NOT NULL REFERENCES buckets(id),
    object_key      TEXT    NOT NULL,
    size            INTEGER NOT NULL DEFAULT 0,
    etag            TEXT    NOT NULL DEFAULT '',
    content_type    TEXT    NOT NULL DEFAULT 'application/octet-stream',
    storage_path    TEXT    NOT NULL,
    last_modified   TEXT    NOT NULL,
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    checksum_sha256 TEXT    NOT NULL DEFAULT '',
    is_corrupt      INTEGER NOT NULL DEFAULT 0,
    UNIQUE (bucket_id, object_key)
);

CREATE INDEX IF NOT EXISTS idx_objects_bucket_key ON objects(bucket_id, object_key);

CREATE TABLE IF NOT EXISTS multipart_uploads (
    id            TEXT    PRIMARY KEY,
    bucket_id     INTEGER NOT NULL REFERENCES buckets(id),
    object_key    TEXT    NOT NULL,
    initiated_at  TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    metadata_json TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS multipart_parts (
    upload_id    TEXT    NOT NULL REFERENCES multipart_uploads(id) ON DELETE CASCADE,
    part_number  INTEGER NOT NULL,
    etag         TEXT    NOT NULL DEFAULT '',
    size         INTEGER NOT NULL DEFAULT 0,
    staging_path TEXT    NOT NULL,
    created_at   TEXT    NOT NULL,
    PRIMARY KEY (upload_id, part_number)
);

CREATE TABLE IF NOT EXISTS access_keys (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    access_key        TEXT    NOT NULL UNIQUE,
    secret_ciphertext TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'active',
    is_root           INTEGER NOT NULL DEFAULT 0,
    description       TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL,
    last_used_at      TEXT
);

CREATE TABLE IF NOT EXISTS ui_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'admin',
    created_at    TEXT    NOT NULL,
    last_login_at TEXT
);
`
