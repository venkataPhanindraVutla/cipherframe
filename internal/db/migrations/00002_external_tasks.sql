-- +goose Up
-- Hand-off table for work done by external (non-Go) workers (ADR 0010). A Go River job writes a
-- versioned JSON envelope here in the same transaction that records the step; an external worker
-- claims rows with FOR UPDATE SKIP LOCKED, holds a lease it extends by heartbeat, and writes back a
-- result envelope. The contract is documented in spec/jobs/README.md.
--
-- The envelope never carries secrets, tokens, signed URLs or source object keys.

CREATE TABLE external_tasks (
    id            uuid PRIMARY KEY,
    kind          text NOT NULL,
    envelope      jsonb NOT NULL,
    state         text NOT NULL DEFAULT 'pending'
        CONSTRAINT external_tasks_state_allowed CHECK (
            state IN ('pending', 'leased', 'succeeded', 'failed')
        ),
    -- Zero-based index of the current attempt; the envelope's attempt is attempts + 1.
    attempts      integer NOT NULL DEFAULT 0 CONSTRAINT external_tasks_attempts_nonneg CHECK (attempts >= 0),
    max_attempts  integer NOT NULL CONSTRAINT external_tasks_max_attempts_positive CHECK (max_attempts >= 1),
    lease_owner   text,
    lease_until   timestamptz,
    result        jsonb,
    river_job_id  bigint,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    completed_at  timestamptz,
    CONSTRAINT external_tasks_envelope_object CHECK (jsonb_typeof(envelope) = 'object'),
    CONSTRAINT external_tasks_envelope_matches CHECK (
        envelope ->> 'task_id' = id::text AND envelope ->> 'kind' = kind
    ),
    CONSTRAINT external_tasks_lease_all_or_none CHECK (
        state <> 'leased' OR (lease_owner IS NOT NULL AND lease_until IS NOT NULL)
    )
);

-- Serves the claim query: the oldest claimable row of the requested kinds.
CREATE INDEX external_tasks_claim_idx ON external_tasks (state, kind, created_at);

-- +goose Down
DROP TABLE external_tasks;
