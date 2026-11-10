# Security policy

Cipherframe protects personal video data, so we take vulnerability reports seriously.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a suspected vulnerability.**

1. **Preferred:** use GitHub's private vulnerability reporting:
   [Report a vulnerability](https://github.com/venkataPhanindraVutla/cipherframe/security/advisories/new).
2. **Fallback:** email **phanivutla2004@gmail.com** with the subject `Cipherframe security`.

Please include:

- the affected version or commit,
- the component (API, edge, worker, CLI, player, SDK),
- steps to reproduce or a proof of concept,
- the impact you believe it has.

Please do not include real personal data or real recordings in a report.

## What to expect

- Acknowledgement within **3 working days**.
- An initial assessment (accepted, needs more information, or not a vulnerability) within
  **10 working days**.
- A fix, an advisory and, where appropriate, a CVE request through GitHub Security Advisories.
- Credit in the advisory if you want it.

We ask that you give us a reasonable time to release a fix (normally up to 90 days) before public
disclosure, and that you avoid privacy violations, data destruction and service disruption while
testing.

## Supported versions

Cipherframe has no release yet. Once v1.0.0 ships, the latest minor release of each supported major
version receives security fixes. The policy will be listed here.

## Scope

In scope: anything that breaks a documented guarantee, for example a source object becoming
browser-addressable, a revoked session still obtaining keys, a deletion leaving readable data behind,
key material or tokens appearing in logs, or a verifier accepting a forged record.

Out of scope, because Cipherframe documents that it does **not** protect against them:

- screen recording or camera capture of playback,
- an authorized viewer keeping a copy,
- scripted reassembly of segments while a session is valid,
- compromise of the operator's own storage or KMS credentials.

Standard HLS AES-128 encryption is not DRM. Reports that video "can be downloaded" by an authorized
viewer are expected behaviour, not a vulnerability.
