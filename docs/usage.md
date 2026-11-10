# Usage

> Status: skeleton (M0-4). Nothing is runnable yet.

## Planned flow

1. Start the stack locally with Docker Compose and MinIO (M1-8). No cloud account is needed.
2. Create an API key for your application.
3. Upload a source video (S3 multipart or tus) and commit it.
4. Wait for the asset to become `ready`.
5. From your server, create a playback session for a viewer you have authorized.
6. Load the returned manifest URL in the reference player.
7. Revoke the session to stop playback at the key endpoint.
8. Delete the asset and fetch its signed deletion record.
9. Verify the record with the public-key-only verifier.

The `cipherframe` CLI (M8-1) covers each step.

## What this does not protect against

See [threat-model.md](threat-model.md#out-of-scope).
