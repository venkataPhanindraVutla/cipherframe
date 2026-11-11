// Package signing manages the Ed25519 keys that sign integrity manifests and deletion records
// (M5-2, ADR 0033).
//
// The keys are deployment-wide: one published key set verifies the records of every tenant. A key's
// seed is generated here, wrapped by the configured KMS provider with the same envelope scheme as
// content keys (ADR 0020) and stored in signing_keys; the public half is published at
// /.well-known/cipherframe-keys.json. A verifier never needs the seed (pitfall 1).
//
// Life cycle of a key: it is created active and current (the one signer). Rotate creates a new
// current key and leaves the previous one active, so it stays published and keeps verifying.
// Retire marks a non-current key retired: it stays published with status "retired" so old records
// still verify, and is never used to sign. Keys are never destroyed in M5.
//
// An unwrapped seed lives in a per-process cache for at most five minutes and is zeroed when it is
// evicted. Nothing in this package logs a seed, a private key or an envelope, and no error it
// returns contains one. A key-service failure is dependency_unavailable (invariant I11) and never
// creates, or uses, a key.
package signing
