# Threat model

> Status: initial (M0-4). Completed in M9-5 once the design exists.

## Assets worth protecting

1. Source recordings (personal data).
2. Content keys and key-encryption keys.
3. Playback tokens and sessions.
4. Derived artifacts: subtitles, transcripts, thumbnails (faces), fingerprints.
5. Access logs (who watched what).
6. Signing keys for integrity manifests and deletion records.

## Actors

| Actor | Trust |
|---|---|
| Operator | Trusted to run the service and hold storage and KMS credentials. |
| Embedding application | Trusted to authorize viewers; authenticated by API key (others pending P7). |
| Authorized viewer | Trusted to watch during a session; **not** trusted to stop there. |
| Unauthorized party | Untrusted; may hold leaked URLs, expired tokens or copied playlists. |
| Verifier | Untrusted; holds only public keys. |

## Threats in scope (initial list)

| Threat | Intended mitigation |
|---|---|
| Original fetched directly | Source bucket private; source key never returned (I4). |
| Segments fetched from storage without a session | Segments are AES-128 ciphertext; keys only via the session-checked key endpoint. |
| Revoked viewer keeps playing | Key endpoint checks session state on every request; revocation is immediate there. |
| Token replay or sharing | Short TTL, scope-limited tokens, bounded replay at the key endpoint, anomaly events (P6). |
| Secrets in logs | Redacting logger; automated scan of a full playback run (pitfall 9). |
| Data survives "deletion" | Storage enumeration, key destruction, re-list, signed record (I5, I6). |
| Forged deletion or integrity record | Signatures verifiable with public keys only (pitfall 1); optional RFC 3161 timestamps. |
| KMS outage reported as success | Fail closed (I11). |

## Out of scope

Cipherframe does **not** protect against:

- screen recording or camera capture of playback,
- an authorized viewer keeping a copy of what they were allowed to watch,
- scripted reassembly of segments while a session is valid,
- compromise of the operator's own storage or KMS credentials,
- any expectation that video "cannot be downloaded": HLS AES-128 is not DRM.

## Known hard limits

- While a transcode runs, plaintext segments exist on the worker's local disk in a private 0700
  directory (ADR 0027). Anyone with root on that node can read them; run workers on dedicated nodes
  with encrypted local disks.

- Losing the key-encryption key makes every asset permanently unreadable. That is the same property
  that makes crypto-shredding work.
- Crypto-shredding cannot reach plaintext a viewer already saved.
