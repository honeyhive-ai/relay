package relay

import "context"

// Exported Store constructors — the binary and any downstream build uses these
// to obtain the built-in backends. (Internal call sites + tests use the
// unexported forms.)

// NewMemoryStore returns an in-process, ephemeral Store (no persistence).
func NewMemoryStore() Store { return newMemoryStore() }

// NewMemoryStoreWithPersistence returns an in-process Store backed by a JSON
// snapshot under dataDir (loaded on boot, flushed periodically).
func NewMemoryStoreWithPersistence(dataDir string) Store {
	return newMemoryStoreWithPersistence(dataDir)
}

// NewPostgresStore returns a Store backed by a shared Postgres (DSN), running
// idempotent migrations on connect. Use for horizontal scaling / HA.
func NewPostgresStore(ctx context.Context, dsn string) (Store, error) {
	return newPostgresStore(ctx, dsn)
}
