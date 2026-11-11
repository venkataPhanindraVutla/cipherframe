-- +goose Up
-- M5-2: integrity signing keys (ADR 0033).
--
-- The keys are DEPLOYMENT-WIDE, not per tenant. A verifier of a manifest or a deletion record
-- fetches one published key set (/.well-known/cipherframe-keys.json) and checks any record with
-- it, whichever tenant owns the asset. The set is public data and carries no tenant information.
-- The audit trail of a rotation or retirement is still written against the admin caller's tenant.
--
--  * private_envelope is the 32-byte Ed25519 seed wrapped by the configured KMS provider, with
--    associated data that binds purpose, key_id and algorithm (package signing). It is NOT NULL
--    and is never cleared: signing keys are NEVER destroyed in M5. A retired key keeps its
--    envelope so that an operator can audit or re-wrap it with the KEK rewrap procedure; it is
--    simply never used to sign again. Destroying a retired key would not make old records
--    unverifiable (verification needs only public_key), so a later milestone may add it.
--  * state is 'active' (published, verifies, and exactly one active key per purpose is the
--    current signer) or 'retired' (published with status retired, verifies, never signs).
--    Several keys may be active at once: that is what a rotation leaves behind.
--  * is_current marks the single signer. The partial unique index enforces at most one.
CREATE TABLE signing_keys (
    key_id           text PRIMARY KEY
        CONSTRAINT signing_keys_key_id_format CHECK (key_id ~ '^sk_[0-9a-hjkmnp-tv-z]{26}$'),
    purpose          text NOT NULL
        CONSTRAINT signing_keys_purpose_allowed CHECK (purpose IN ('integrity')),
    algorithm        text NOT NULL
        CONSTRAINT signing_keys_algorithm_allowed CHECK (algorithm IN ('ed25519')),
    public_key       bytea NOT NULL
        CONSTRAINT signing_keys_public_key_len CHECK (octet_length(public_key) = 32),
    private_envelope bytea NOT NULL
        CONSTRAINT signing_keys_envelope_nonempty CHECK (octet_length(private_envelope) > 0),
    state            text NOT NULL
        CONSTRAINT signing_keys_state_allowed CHECK (state IN ('active', 'retired')),
    is_current       boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    activated_at     timestamptz NOT NULL DEFAULT now(),
    retired_at       timestamptz,
    CONSTRAINT signing_keys_retired_consistent CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
    CONSTRAINT signing_keys_current_is_active CHECK (NOT is_current OR state = 'active')
);

CREATE UNIQUE INDEX signing_keys_one_current_idx ON signing_keys (purpose)
    WHERE state = 'active' AND is_current;
CREATE UNIQUE INDEX signing_keys_public_key_idx ON signing_keys (public_key);
CREATE INDEX signing_keys_created_idx ON signing_keys (created_at, key_id);

-- +goose Down
DROP TABLE signing_keys;
