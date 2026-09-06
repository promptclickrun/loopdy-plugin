# Workspace Files foundation

Status: source candidate for review. This is a plugin-side API/CLI feature, not an enabled mobile Files screen. Mobile and encrypted Link integration are a later phase.

## Ownership and access

The host operator grants a specific existing directory to an opaque workspace ID. A grant is a read-only file-access permission, not a Hermes Project or session record. Hermes remains authoritative for its own Projects/sessions; this service neither reads their private databases nor registers/moves them.

No roots are granted by default. Remote API callers cannot create, change or revoke grants. A grant cannot silently change to another directory; revoke it before granting the replacement. Only the configured profile's plugin data stores grants. The regular host plugin-API authentication governs remote callers, who may inspect all grants exposed by that host/profile. This initial API is **not a per-device Link grant** or a session-bound access token.

```text
local operator → explicit read-only root grant
                          ↓
  host CLI / authenticated plugin API
                          ↓
         validate workspace ID + relative path
                          ↓
      open beneath pinned root, reject links
                          ↓
      bounded listing / file bytes / Git diff
                          ↓
       recheck grant + version → return result
```

## Intended client behavior

- Discover configured roots and capabilities before browsing.
- Keep the selected workspace ID as authority. Never send a client-supplied absolute path.
- Empty relative path means Root. `parent: null` means already at Root; `parent: ""` means Up returns to Root.
- Listing is directory-local and folders sort first. Name search is not a recursive repository index.
- Follow explicit pagination metadata; never describe a partial list as complete.
- Keep the returned revision and send it on later pages. If the directory/file changes, start again rather than combine versions.
- File bytes use Base64 solely as JSON transport encoding, not encryption. A UTF-8 convenience field does not replace the exact bytes.
- Render content inertly. Do not execute files, scripts, HTML, links or embedded commands. No write/edit/delete/rename/commit/push method is exposed by this service.
- Git status/diff uses fixed commands in the existing plugin Git engine with only its status capability enabled. Existing Git mutation endpoints are unchanged and are not granted by a Files permission.
- A non-Git folder remains browsable and returns an explicit Git-unavailable result for Git requests.

## Security limits

Directory traversal, absolute/drive/UNC paths, symlinks (including links staying within the root), unsafe hard links, special files/FIFOs, credential/control paths and known secret patterns are refused or omitted. Root identity is pinned so directory replacement invalidates the grant. Revocation is rechecked, including after I/O. Completed content already seen by a client cannot be recalled.

Whole eligible files are scanned for the plugin's known credential patterns before returning any chunk. This is conservative pattern matching, not a claim to detect every possible secret or fully inherit Hermes's evolving file-tool policy. Human review of the granted directory remains important. Compressed/binary content can contain data that text-pattern scanning cannot recognize; clients must treat all bytes as untrusted.

The file ceiling is 8 MiB and chunks are at most 64 KiB. Oversized files have explicit unavailable metadata, never a misleading truncated preview. Listings and JSON responses are bounded independently. No recursive watcher/index or durable content cache is created.

Secure descriptor-relative traversal is required. The first implementation supports capable POSIX hosts and fails closed on Windows/hosts without those primitives. A future Windows implementation must provide equivalent reparse-point and handle-relative containment before advertising support.

## Supported extension surface

The existing `dashboard/manifest.json` names the plugin's `plugin_api.py`, which exports an `APIRouter`; stock Hermes mounts it beneath `/api/plugins/loopdy` with the host's authentication. Files routes are a focused child router. The host CLI is registered through `ctx.register_cli_command` and the existing `loopdy` command. No additional listening service, private runtime API, core patch, or new dependency is required.

Official references:

https://hermes-agent.nousresearch.com/docs/developer-guide/desktop-plugin-sdk
https://hermes-agent.nousresearch.com/docs/developer-guide/plugins

## Host commands

After this candidate is reviewed, merged and installed, the registered commands are:

```sh
hermes loopdy files grant demo --root /absolute/path/to/project --label 'Demo project'
hermes loopdy files roots
hermes loopdy files list demo --path '' --limit 100
hermes loopdy files list demo --path docs --query readme
hermes loopdy files read demo README.md
hermes loopdy files status demo
hermes loopdy files diff demo README.md --side worktree --expected-status-token "$STATUS_TOKEN"
hermes loopdy files revoke demo --yes
```

The example root is a placeholder for a directory the operator explicitly approves. `STATUS_TOKEN` is the exact `status_token` returned by the preceding status request. Listing/read pagination accepts `--offset`, `--limit` and `--revision`; diff pagination accepts `--offset` and `--limit`. Failed commands print a structured, path-redacted error and exit nonzero. Revocation requires `--yes`. Grant/revoke changes affect this plugin's permissions only and do not alter Hermes Projects.

## API contract, schema version 1

All paths below are relative to the stock `/api/plugins/loopdy` mount. Host authentication is required. Link pairing credentials do not authorize these routes; do not ship a mobile origin/token fallback. A future Link adapter must enforce its own verified device boundary and the same host grants.

| Method / path | Request | Result |
| --- | --- | --- |
| `GET /workspace-files/capabilities` | None | Read-only/security flags, limits, granted opaque IDs and labels |
| `POST /workspace-files/list` | `workspace_id`, optional `path`, `query`, `offset`, `limit`, `revision` | Relative `path`, `parent`, `entries`, `total`, `offset`, `limit`, `next_offset`, `revision` |
| `POST /workspace-files/read` | `workspace_id`, `path`, optional `offset`, `limit`, `revision` | `availability`, `size`, `data` (Base64), optional complete `text`, `next_offset`, `revision` |
| `POST /workspace-files/status` | `workspace_id` | Existing structured Git status plus `hidden_files` |
| `POST /workspace-files/diff` | `workspace_id`, `path`, `side`, `expected_status_token`, optional `offset`, `limit` | Existing structured Git diff rows, availability, and next offset |

A listing entry contains `name`, relative `path`, `kind` (`directory` or `file`) and `size` (null for a directory). `total` describes all matching visible entries in that directory snapshot. A byte-bounded response may contain fewer than the requested `limit`; continue from `next_offset`.

File availability is `available`, `binary` or `oversized`. Binary chunks still carry inert bytes; their `text` is null. Complete UTF-8 text is supplied only when the file fits in one chunk and the total JSON stays bounded; clients must support the authoritative bytes when `text` is null. Byte offsets address bytes, not Unicode characters. Revision is the SHA-256 of the complete file, with a `sha256:` prefix. An oversized result carries no bytes/revision and cannot be paged as a preview.

Git status omits protected paths. `hidden_files` counts those omitted rows, `changes`/`files_page` describe visible rows, and repository `dirty`, staged/worktree counters and head metadata retain the underlying Git meaning. Status projections exceeding the existing Git engine's complete-list bounds fail with `GIT_STATUS_OVERSIZED`; they are never relabeled complete. Structured diffs scan all generated hunks once before selecting a page, so a secret in a later hunk blocks the first page as well. Protected rename origins are not exposed.

Errors use `error: {code, message, retryable, details}` with sanitized text. Invalid request bodies return 422; invalid paths/missing revisions 400; missing/protected grants or paths 404; stale revisions/status 409; detected credentials or unsafe hard links 422; oversized listings/status 413; unsupported secure traversal 501; unavailable local/Git state 503. Errors while constructing the API dependency use FastAPI's `detail` wrapper around that envelope. No raw exception or absolute root is returned.

## Verification

From a standalone checkout, use a fresh temporary `HERMES_HOME` and the installed Hermes Python environment, with the candidate directory first in `PYTHONPATH`:

```sh
PYTHONPATH="$PWD:/path/to/hermes-agent" \
  /path/to/hermes-agent/venv/bin/python \
  -m unittest discover -s tests -p 'test_workspace_files*.py' -v
```

The focused tests exercise real files and Git repositories, opaque-byte pagination, revocation during I/O, root replacement, path/link/credential refusals, registered CLI commands, actual stock plugin discovery/mount, authentication denial and runtime disablement. The host-mount and CLI tests create their own credential-free temporary homes and do not modify a live installation. Existing Git, registration and Link contract suites remain relevant compatibility checks. Native Windows secure traversal is not implemented or verified.

## Delivery boundary

Review and merge this foundation before adapting mobile clients. The existing Link operation allowlist and capability envelopes remain unchanged. A later integration must bind the mobile account/host/workspace, negotiate the new operations without breaking older strict clients, and preserve the same grant enforcement. A public PR is not an installation, restart, app release or proof of live mobile availability.
