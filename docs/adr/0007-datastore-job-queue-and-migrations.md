# 0007. Datastore, job queue and migrations

- Status: Accepted
- Date: 2026-11-10
- Gate: P2
- Deciders: project owner

## Context

M1 needs a datastore and a job queue with resumable jobs, retries and a dead-letter list (M1-5).
Deletion correctness depends on database state changing in the same transaction as the jobs that act
on it. A Python ML worker will consume some jobs in v2.1 (P21).

## Options considered

1. **Postgres only, with a queue we write** (`SKIP LOCKED` claims): one stateful service; we own the
   queue code.
2. **Postgres + River**: mature Postgres-native Go queue (MPL-2.0) with transactional enqueue; its
   protocol is River's own.
3. **Postgres + Redis (Asynq)**: second stateful service; enqueue not transactional; Go-centric
   payloads.
4. **Postgres + NATS JetStream**: language-neutral; second stateful service plus an outbox.

Migration tools: goose, golang-migrate, Atlas.

## Decision

- **Postgres** is the only stateful dependency. The minimum supported version is set when the
  Compose file pins one in M1-8.
- **River** (`github.com/riverqueue/river`, MPL-2.0, which the licence allowlist permits) runs Go
  jobs. Jobs are inserted in the same transaction as the state change that requires them.
- River's own retry, backoff, discard and snooze features cover retries and the dead-letter list;
  Cipherframe exposes discarded jobs through its own API and CLI rather than River's UI.
- The queue sits behind a Cipherframe interface so job handlers don't depend on River types directly.
- **goose** (MIT) runs migrations from plain SQL files embedded in the binary; `sqlc` reads the same
  files to generate typed queries (ADR 0004).
- River's own schema migrations are applied through River's migrator as a versioned step of the same
  migration run, so a single command brings a database up to date.

## Consequences

- No second stateful service for self-hosters.
- Python cannot work River jobs; cross-language work goes through a hand-off table (ADR 0010).
- Upgrading River may bring schema migrations; they are pinned and tested like ours.
- If queue volume ever outgrows Postgres, the interface above is the seam for replacing it.
