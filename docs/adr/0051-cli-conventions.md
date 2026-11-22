# 0051. Command line tool conventions

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M8-1a)
- Deciders: project owner (the M8-1 scope); the choices below are flagged for review

## Context

M8-1 turns `cmd/cipherframe` (so far `verify`, `version` and `help`, all offline) into the full
command line tool. M8-1a builds the framework and the asset commands; M8-1b adds the remaining
commands (sessions, subtitles, brand, keys, webhooks, `verify-file`, `proof`) on the same
framework. Conventions that every later command inherits are fixed here.

## Decision

- **Typed client generated from the spec.** `internal/apiclient` is generated from
  `spec/openapi.yaml` with oapi-codegen (the version the server already uses), for the operations
  tagged `api`, by `go generate ./...`; CI already fails when generated output is stale. The raw
  generated `HTTPClient` is used (it returns `*http.Response`), and the CLI decodes bodies itself
  so it can print the server's JSON unchanged. The generated type is renamed `HTTPClient` because
  the spec has a schema called `Client`. The tus endpoints are not in the generated set (they are
  not an API client concern) and are written by hand.
- **Settings.** `--server` or `CIPHERFRAME_SERVER` (required, `http(s)`, no credentials; there is no
  default, so a command never talks to a server the operator did not name). The API key comes from
  `CIPHERFRAME_API_KEY` or a file named by `--api-key-file`; there is no flag that takes the key
  (shell history, process listings). `--timeout` (default 30 s) bounds each request, not the whole
  command; a tus chunk gets five times that. The edge URL is read from the create response, never
  configured. Every server command takes these flags after its name, and flags may follow the
  positional arguments (`upload FILE --wait`). There are no global flags before the command.
- **Output.** Human output goes to stdout for results and stderr for progress and diagnostics.
  With `--json`, stdout carries one JSON document that is the server's own response, unchanged
  (`status` prints a small fixed object), and errors are one JSON object on stderr:
  `{"error":{"code","detail","exit_code", and for API errors "status","request_id","retryable","limit"}}`.
  `upload` prints the bare asset ID so `id=$(cipherframe upload f.mp4)` works. `delete --wait` and
  `deletion-record` print the signed record (the DSSE envelope) on stdout in both modes, so the
  output can be saved and given to `cipherframe verify --deletion-record`.
- **Problems.** An RFC 9457 problem is shown as `title: detail (code C, request id R)` plus the
  quota `limit` when present. Every printed string is scrubbed of the API key and the upload token,
  so a server that echoed them back would still not leak them; transport errors drop the URL.
- **Exit codes** (verify keeps 0 to 2; usage is 3 everywhere):

  | Code | Meaning |
  |---|---|
  | 0 | success (verify: all ours) |
  | 1 | verify: any file modified |
  | 2 | verify: cannot say |
  | 3 | usage error (bad flag or argument, missing server or key) |
  | 4 | the server refused the request (401, 403, 400, 413, other 4xx, 500) |
  | 5 | not found (404, including `not_deleted`) |
  | 6 | conflict or quota (409, 429) |
  | 7 | no answer: network error, timeout, 502 to 504 |
  | 8 | `--wait` ended without success: the asset failed, was deleted, or the wait timed out |

- **tus with the standard library.** The protocol subset needed is small (creation, HEAD, PATCH
  with `Upload-Offset`), so no tus client dependency is added. The client sends only the length (no
  `Upload-Metadata`, so no file name, ADR 0040). It sends chunks of 8 MiB; after a failed chunk
  (network error, 502 to 504, or a 409 offset mismatch) it asks the server for the offset with HEAD
  and continues from there, up to five consecutive failures without progress with exponential
  backoff. The upload token is sent only to the host that served the creation request: a `Location`
  on another host is refused.
- **Resume across runs is not offered.** The upload token is shown once and is never stored on disk,
  so a killed `upload` cannot be resumed by a new process; the asset expires or is aborted through
  the API. Resume is within one run. Storing the token would trade a secret on disk for convenience.
- **`--wait`** polls `GET /v1/assets/{id}` every second, growing by half each time up to 10 s, with
  `--wait-timeout` (default 30 min). Network errors and 502 to 504 while polling are retried until
  the deadline.
- **`process`** exists as a documented alias of the commit call: the API has no separate processing
  trigger (commit queues it). `upload` already commits; `process ID` is for retrying a commit that
  was refused (for example a storage quota) once the cause is fixed.
- **Content type.** Taken from the file extension (a small table plus the platform's), overridable
  with `--content-type`, omitted when unknown. Only the extension is used, never the name.
- **`--ttl`** accepts Go durations and `Nd` days (1 minute to 3650 days) and sends `ttl_seconds`.

## Consequences

- Spec changes reach the CLI through `go generate`; the client is about 28k generated lines, which
  already covers M8-1b's operations.
- Tests run the CLI against an httptest server that validates every API request and response against
  the spec, and check that neither secret reaches any output.
- Not covered: cross-process upload resume, a configuration file or profiles, shell completion,
  coloured output, and multipart uploads (the CLI uses tus only). Revisit if operators ask.
