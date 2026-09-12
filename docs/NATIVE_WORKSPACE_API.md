# Native workspace plugin foundation

These routes extend stock authenticated `hermes serve` at `/api/plugins/loopdy`.
They do not use the plugin's paired Direct listener or require a Loopdy account.
Network/Tailscale/TLS configuration and host activation remain operator-owned.
Stock Hermes REST and `/api/ws` still own native chat and workspace execution.

This is not full native parity. Optional
[room tool observations](NATIVE_ROOM_ACTIVITY.md) extend this foundation on
supported main builds. [Native Wiki](NATIVE_WIKI.md) uses the same verified
principal without extra pairing. Phone-tool and personalized hosted-group
ingress remain separate proof-gated capabilities.

## Authentication and context

`GET /api/plugins/loopdy/native/context` takes no query parameters or body:

```text
{
  schemaVersion: 1,
  pluginVersion: string,
  runtimeId: string,
  servingProfileId: string|null,
  principal: {provider: string, userId: string, displayName: string|null},
  features: string[]
}
```

The route requires a real verified Hermes `dashboard_auth.base.Session` from
the native bearer/cookie middleware, including on a loopback host. A legacy
dashboard token, service principal, body actor, or display/device header cannot
substitute. Only provider (128 UTF-8 bytes), user ID (512) and optional display
name (200) are copied. Tokens, email, org metadata and the Session object are
never returned or logged. Display names are presentation, not authorization.

The app must match provider/user ID to `/api/auth/me` at the selected endpoint.
Its auth/connection generations are local stale-callback fences, not server
credentials. Native workspace access does not imply a per-profile principal ACL
or any phone permission.

`runtimeId` identifies this loaded native plugin HTTP module lifetime, not
installed source, release freshness, Link identity, or a device. Process profile
is obtained only with the public
`profile_name_for_home(get_process_hermes_home())` helpers, ignoring request-local
home overrides. Missing/unproven profile is null, never inferred as `default`.
The filesystem path is not exposed. Use this proof to gate process-scoped
memory/logs/webhooks; an ignored `?profile` is not scope selection.

Features are finite: `native-context-v1`, `serving-profile-v1` when proven, and
`native-card-templates-v1` when the implemented routes' public profile helpers
are available. `native-room-activity-v1` is added only with an actual supported
live public-hook registration. These are not universal Hermes capability or runtime health claims.
`native-wiki-v1` advertises the fixed principal-owned Wiki adapter on secure
traversal platforms; folder policy and local journal availability still apply.
Read failures remain visible. Context responses are at most 16 KiB.

## Card templates

Successful context GET returns `Cache-Control: no-store` and an `ETag` of the
form `"sha256:<64 lowercase hex>"` (including quotes). It hashes canonical JSON
of the safe context above; it is a precondition, NOT a credential.

Every template POST requires that exact `If-Match` plus
`X-Loopdy-Request-ID: <canonical lowercase UUID>`. Duplicate, missing or malformed
headers fail. Success echoes both headers. Valid request IDs are also echoed on
plugin validation/domain errors; errors do not issue a new ETag. Stock auth and
disabled-plugin errors may originate before the plugin and have no echo.

All paths below start `/api/plugins/loopdy/native/cards/templates/`:

| POST suffix | Exact JSON body | Successful result |
| --- | --- | --- |
| `list` | `{agentId}` | `{agentId,templates:[summary]}` |
| `install` | `{agentId,template:bundle}` | `{agentId,changed,template:summary}` |
| `remove` | `{agentId,templateId,version,sha256}` | `{agentId,changed,templateId}` |

An exact existing canonical profile ID is required. No fallback, arbitrary
method/path, actor/device/host override or new remote template fetching is
accepted. All three routes reuse the serving plugin's existing profile-keyed
template store and the same summary projection as Link.

Summary fields: `id,version,name,summary,author,license,minimum_card_version,sha256`.
Bundle adds exactly `parameters_schema,document`; see
[`loopdy-card-template-v1.schema.json`](../spec/loopdy-card-template-v1.schema.json).
Native version fields are strict integers, card version is 1, the document hash
must match, and the existing inert Card validator prohibits active data sources.
Requests/responses are at most 196608 UTF-8 bytes, JSON depth at most 24 and
catalogs at most 500 summaries. Oversized catalogs fail rather than silently
truncate. Duplicate JSON fields, non-finite numbers and unknown fields fail.

Identical full-bundle reinstall is unchanged; same-version different content or
downgrade conflicts. Remove compares exact version/hash; already absent is
unchanged. These are existing domain outcomes, not a general request-ID receipt
or exactly-once protocol. Cancel/disconnect/context change can race a committed
transaction: reconcile by listing under a fresh context, never blindly retry a
mutation or switch transports. Context is checked before/after body and worker
awaits. Native auth revocation is enforced by stock middleware on new requests,
not a new atomic revoke-versus-in-flight-transaction guarantee.

Plugin errors are `{error:{code,message,retryable,details:{}}}`. Statuses: 401
missing/invalid interactive identity; 404 missing profile; 422 invalid input;
428 missing If-Match; 412 changed context; 409 template conflict; 413 bound
exceeded; 503 unavailable service. Errors are bounded and omit raw inputs,
exceptions and paths. A 412 requires a fresh context; it never authorizes retry.

## Existing services are separate contracts

Existing routes and older clients are unchanged; the new headers are not
required by forms, attachments, provider/device management or Files:

- Forms: `/generative-ui/v2/forms/{request_id}/submit` and `/status`, with
  existing stored profile/session binding and action-response envelope.
- Attachments: `/attachments/resolve` and `/attachments/{id}?profile=...`,
  using existing Hermes delivery policy and opaque profile cache IDs. This is
  not a universal artifact catalog or authenticated-person/turn proof.
- Files: `/workspace-files/capabilities`, `/list`, `/read`, `/status`, `/diff`.
  Explicit host-local root grants are required in addition to HTTP auth. The
  current serving-profile catalog is shared by its authenticated workspace
  callers, not a per-device ACL. See [Workspace Files](WORKSPACE_FILES.md).

Plugin Files uses opaque IDs and relative paths, not native Files absolute
`locked_root` paths. Its grant generation/inode checks are internal; wire
revisions are file hashes or directory snapshots, not client-visible grant
epochs. Retain the native owner and proven process profile over each await and
re-probe roots after reconnect.

## Capability boundaries

| Capability | Current native boundary |
| --- | --- |
| Wiki | Native Session principal/profile ownership shares the existing registry/lock, with no additional pairing. Link ownership stays separate; existing Link roots are not adopted. See the exact native Wiki contract and versioned storage boundary. |
| Phone tools | Registration/poll auth alone cannot bind a native model/tool turn to a verified phone. No public generic ToolExecutionContext override in native prompt ingress was verified; ordinary chat stays native. |
| Hosted person context | Public pre-LLM hooks lack authoritative hosted room/member/discussion/task-generation/person binding. Generic native durable actor remains honest; no private/task-title/text inference. |
| Group activity | Optional main-only public observer feeds are asynchronous, lossy and local-member-only; see the exact HTTP polling contract. No durable replay or completion-success inference. |
| Group result size | Link negotiates `groups-results-v1` separately; native room readiness still requires protocol 2 and a running driver. See [PROTOCOL](../PROTOCOL.md). |

Native auth is not a phone grant; optional cloud account erasure does not revoke
independent native credentials. Raw microphone transcription remains local to
the phone, and provider credentials are never exposed by these routes.

## Verification and activation

`tests/test_native_api.py` covers real Hermes auth middleware and stock serve
plugin discovery in synthetic homes, not a substitute production auth provider.
Focused groups, Link, templates, forms, attachments and Files suites cover
compatibility. Use the real Hermes Python with explicit source/candidate import
paths and a credential-free temporary HOME/HERMES_HOME before any imports.
No installation, restart, deployment, release or activation follows from these
source changes or their passing tests.
