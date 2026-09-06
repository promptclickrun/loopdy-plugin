# Loopdy protocol

Plugin release `2.4.0` adds authenticated, restart-safe plugin update start/status
operations and durable exact-revision activation evidence. Plugin release `2.3.0`
adds real session update/delete and skill get/create/update/import
handlers, capability discovery, correlated workspace rejection, and bounded Link
backpressure recovery. Encrypted Link frames remain wire version 1.

Plugin release `2.2.15` adds complete Markdown preview content for project diffs and bundled custom-theme authoring guidance. Release `2.2.14` compares Project roots by filesystem identity so macOS case variants identify the same registered repository.

Plugin protocol version 2 keeps Hermes authoritative for sessions, policy, approvals, event details, and the local notification ledger. Plugin release `2.2.13` reconciles persisted session activity with the live Loopdy owner and gives concurrent picker requests exact request identity, including correlated failure when Hermes returns without a native picker. Release 2.2.12 restored a persisted Project into both Hermes' task-local agent context and terminal session registry after gateway startup, and deterministically projected sessions newest-first. Release 2.2.11 restored the selected Project into Hermes' task-local runtime CWD after the gateway binds session variables, so agent prompt construction and explicit terminal workdirs stay anchored to the session workspace without process-global state. Release 2.2.10 aligned Project selection with Hermes' native session lifecycle: new chats seed the selected CWD before first-turn creation without persisting an empty session, while existing chats persist the moved CWD, update the live tool runtime immediately, and evict cached agent context for the next turn. It also projects Hermes native image, document, video, and voice callbacks through the authenticated attachment resolver, including media delivered after streamed text. Release 2.2.6 projects request-bound Clarify attention through the encrypted Link notification path while keeping the opaque Link chat coordinate separate from Hermes' pending-session key, so the active chat, Home card, notification, and official Clarify resolver address the same request without weakening either coordinate boundary. Replayed events retry failed Link delivery but do not duplicate an event already recorded as sent. Release 2.2.5 made inbound attachment storage self-healing and retained verified media until Hermes' background processing lifecycle completed, preventing one missing cache directory or prematurely deleted image from stalling the shared Link transport. Release 2.2.4 added optional authenticated mid-session `steer`, `queue`, and `interrupt` behavior on the existing Link user-message envelope, plus fail-soft display sanitization for control scalars inside otherwise valid history-row content. Release 2.2.3 added bounded, cursor-like paging to session history so large transcripts and saved Generative UI payloads can be restored without exceeding the encrypted workspace-response limit. Release 2.2.2 derived Generative UI provenance age from signed timestamp facts at every renderer boundary so normal tool or transport delay cannot invalidate an otherwise truthful card. Release 2.2.1 added explicit correlated picker-open failures and complete compacted-session hydration to the fixed encrypted workspace-control family introduced in 2.2.0. The optional authenticated HTTPS notification-delivery path was introduced in 2.1. Link and notification relay wire contracts are independently versioned as version `1`. Neither service becomes a session, approval, or history authority.

## Read-only workspace Files API

The plugin-side Files foundation is specified in [Workspace Files](docs/WORKSPACE_FILES.md). It exposes only host-granted roots through the supported authenticated plugin API and local CLI. It does not add operations to the current encrypted Link allowlist or alter capability/ready envelopes. Future Link/mobile integration must negotiate its contract explicitly and enforce the same root grants.

## Loopdy Link

Each Loopdy account owns a single per-account Durable Object that coordinates multiple revocable phone, tablet, and Hermes-host device identities. Account signup uses a passkey and stores no email address, password, phone number, or profile record. Device display names and chat frames are encrypted with the account key before they leave a device.

`hermes loopdy link pair` creates a short-lived challenge, ephemeral claim secret, P-256 signing identity, and X25519 agreement key. It derives a SHA-256 commitment over the flow, device coordinate, signing key, and agreement key. The locally constructed QR URL carries the full commitment; manual pairing requires the separately displayed 16-character fingerprint. The app recomputes the commitment from inspected service data and refuses to release the account key on mismatch. The plugin ignores any service-supplied pairing URL. The host receives its account-key grant only after proof of possession, then persists the final origin, opaque device coordinate, authorization epoch, account key, and private keys through Hermes' configuration writer. The temporary claim secret is not retained.

The host opens an outbound `wss://link.loopdy.app/v1/socket` connection, so Linux, macOS, and Windows installations require no inbound port forwarding. Every socket request is device signed. Every chat payload is account-key AEAD ciphertext with sender epoch, monotonic sequence, acknowledgement, retry, replay rejection, and bounded offline delivery semantics.

Clients that support durable reconnect reconciliation add the fixed
`x-loopdy-capabilities: socket-ready-v1,backpressure-v1` capability to that signed upgrade
request. After authentication, the Link service sends a `socket.ready` control
frame containing the authenticated device coordinate, authorization epoch,
server inbound high-water sequence and exact last frame ID, plus the server's
acknowledgement high-water, before replaying queued frames. The client waits for
this frame before marking the socket verified or replaying its pending outbound
frame. A pending frame that exactly matches the reported sequence and ID is
settled as an accepted lost response; a conflicting frame is re-enveloped at
the next server sequence while retaining its decrypted payload. If the server
reports the immediately preceding sequence, the pending frame retains its
durable identity. Clients with no capability receive no `socket.ready` frame,
so legacy Hermes hosts continue to receive only their existing protocol
messages. Inbound frames at or below a client's committed sender high-water are
receipted as duplicates. Fresh frames must authenticate before their sender
high-water advances. Sender sequences are account-wide: gaps in one host's
observations are valid and do not require consecutive per-host sequence numbers.

Verified interactive turns enter Hermes through the official platform adapter. A bounded pre-LLM hook adds the registered actor and device context for that turn; cron and other non-interactive work do not inherit it. The plugin is not a generic command proxy and exposes no arbitrary host execution route.

Every parsed `user.message` receives an encrypted, coordinate-bound `user.message.result` after the Hermes callback completes. It repeats the exact request, session, and agent IDs and carries either `accepted`, or `failed` with a bounded code and user-safe message. `accepted` means Hermes accepted the request; it is not an assistant final. The host sends this result before receipting the inbound request, and its ordered dispatcher does not allow a later callback to overtake a blocked result. Assistant draft frames are presentation hints and are rate-limited per active turn to one every 250 milliseconds; final responses, tools, approvals, attachments, and canonical Hermes history are never reduced by that throttle. Callback rejection and unavailable attachments therefore settle the owning normal, steer, or queued request promptly. Expired authenticated `host_relay` enrollment is quarantined in order without retrying the expired lease; `link_wake` handling is unchanged. Other relay-readiness, protocol, and transport failures remain unreceipted rather than being misreported as Hermes rejection.

An outbound delivery watchdog marks only its exact durable pending frame as failed and establishes a fresh signed socket. The authenticated `socket.ready` state commits an exact accepted frame; every other authenticated high-water abandons the already-visibly-failed frame without replay and re-anchors the client's outbound sequence to the relay. This prevents a failed frame from poisoning future launches while ensuring the next payload uses the relay's exact next sequence. A later payload keeps the same account and device identity and can proceed after that adjudication. The relay enforces one socket owner per device identity and closes the superseded owner with private code `4000`; clients treat that close as terminal for the old connection loop rather than reconnecting it to displace the newer owner.

Paired clients can also send the fixed `workspace.request` family over the same encrypted socket. Version 1 allowlists only agent listing/creation/update, session listing/history/update/delete, skill listing/get/create/update/import, scheduled-task listing/mutations, three-scope agent defaults, bounded Hermes Project listing/selection/creation/archive, project-folder suggestions, dashboard dismissal, and request-bound approval operations. Each `workspace.result` repeats the exact request ID and operation; clients reject mismatched coordinates. The host adapters call Hermes-owned profile, Project, session, cron, model-options, configuration, and plugin-store functions. Agent-default reads are profile-scoped through Hermes' native `config.get` and `model.options` methods; only installed Hermes releases without those methods use the older dashboard function signatures. Requests cannot supply a URL, route, shell command, credential, or generic Hermes method. The sole filesystem-bearing family is the explicit Project manager: creation accepts one existing canonical directory, and `projects.list_directory` returns bounded/paginated directory names and paths only. It never returns file entries or contents, rejects traversal and control characters, skips hidden/build directories and symlink children, and relies on the authenticated host process's read/search permissions.

Scheduled-task delivery stays on Hermes' cron contract. `scheduled_tasks.delivery_targets` projects the bounded result of `cron.scheduler.cron_delivery_targets()` without environment values, while create/update write only the official `deliver` field. A manual destination must use a platform returned by that catalog and the canonical `platform:chat_id[:thread]` form; the plugin never guesses a home target. Inline Generative UI remains on the active conversation response path and is not copied into notifications. A proactive or scheduled Inbox card explicitly targets `loopdy`. Hermes passes that channel adapter the complete final delivery text plus ordinary metadata, not prior renderer-tool results, so the exact validated renderer envelope must be the complete delivered content. Missing, invalid, or prose-mixed content remains a text event. The adapter also recognizes Hermes' exact cron response wrapper only when its embedded job identity matches the official `job_id` metadata, then applies the same renderer validation. No script, reconstructed envelope, or auxiliary delivery API participates in either pathway.

Picker opens use the same request-bound control path. If Hermes cannot construct a requested picker, the plugin returns a failed `picker.result` containing the exact picker, session, and kind coordinates so the client can end its loading state immediately. Session-history requests explicitly include Hermes compacted rows and prefer non-empty `display_content` when it is a string, otherwise falling back to the persisted `content`; tool rows remain excluded from the chat transcript projection. The original `{storedId, agentId}` `sessions.history` payload remains valid, while clients may add a nonnegative `offset` to page backward from the latest message. Each returned page stays chronological and below the Link response budget; `nextOffset` is present only when an older page may remain.

Session-history responses may also carry an optional `runtime` object on the initial page: `{"model":"selected-model","provider":"provider-id"}`. Model and optional provider labels are bounded to 160 and 128 bytes. The projection reads the exact profile-owned durable row and, where ownership still matches, its current persisted session override through Hermes' session-store API. It never exports model configuration, credentials, or provider URLs. Missing or malformed runtime metadata does not block transcript hydration. Existing clients ignore the additive field; clients without a known session model display an unknown session label rather than presenting agent defaults as session authority. Live context observations can update the displayed executing model without opening a picker or issuing a slash command.

Authenticated `activity.event` tool rows may include the bounded canonical `toolName` coordinate plus `arguments` and `result` text so a paired client can label the folded row and disclose exact tool detail on demand. Those fields are valid only for canonical tool-call coordinates, reject unsafe control characters, and are never copied into the separately sanitized Live Activity or APNs projection.

### Workspace capability discovery and rejection

A client opts in to optional workspace metadata using the existing read-only
`agents.list` operation with payload `{"linkProtocol":1}`. The top-level request
remains exactly v1: `version`, `type`, `requestId`, `operation`, `payload`, `sentAt`.
The host recognizes only integer `1` (not boolean `true`), removes the reserved
probe key before normal controller execution, and remembers support for that
authenticated sender in a bounded 256-device LRU registry until adapter shutdown
or eviction. Negotiation does not add an operation or bypass controller checks.
A mutation or an unknown operation must never be used as a probe.

Replies to requests from unnegotiated devices omit `capabilities` and `context`
completely, preserving the strict legacy result shape. Negotiated replies include
`capabilities` with `protocolVersion: 1`, `pluginVersion: "2.4.0"`, features
`["workspace-rejected-v1", "backpressure-v1", "plugin-update-v1"]`, and `operations` generated by sorting
the actual `WORKSPACE_OPERATIONS` set. The controller checks that its handler map
matches that set. A legacy host may ignore or reject the safe probe; updated
feature clients still send their ordinary request afterward. Unknown metadata
blocks only the six capability-gated operations (`skills_tools.get/create/update/import`
and `sessions.update/delete`), not existing reads. Low-level recovery requests do
not require feature negotiation. Probe work is single-flight and socket-owned;
cancelling a UI waiter does not cancel shared discovery or strand its outbound slot.
Client metadata belongs to the exact credentials, selected host, logical connection,
and physical transport generation, and is reset at reconnect, stop, or authority change.

### Plugin update operations

The optional `plugin-update-v1` feature advertises two finite workspace operations.
`plugin_update.start` accepts exactly
`{"operation_id":"opaque_16_to_128","confirm_restart":true}`. The operation ID
uses ASCII letters, digits, `_`, or `-`; confirmation must be boolean `true`.
`plugin_update.status` accepts either `{}` or the same `operation_id` coordinate.
Neither request accepts a device, host, repository, ref, executable, command, or
path. The host binds both operations to the authenticated encrypted-frame sender
and its current profile.

Both operations return one flat, bounded payload with `operation_id`, `phase`,
`target_revision`, `installed_revision`, `active_revision`, `runtime_id`, and
`message`. It contains no credentials, paths, subprocess output, scanner report,
or raw exception text. Empty status is `idle` and reports only safe installed and
active revision evidence; absent optional IDs/revisions use JSON `null`. Public progress phases are `accepted`, `resolving`, `validating`, `installing`, `restarting`, and `waiting_for_activation`. Reusing an operation ID with the same authenticated
device and restart choice returns the durable operation; conflicting ownership or
payload fails closed. Terminal phases are `complete`, `up_to_date`,
`installed_restart_required`, `blocked`, and `failed`. `timed_out` retains ownership until later reconciliation, so it cannot start a second update.

`complete` is stronger than process liveness: the target SHA must match the
revision snapshotted when the new plugin module loaded, the runtime nonce must be
fresh relative to the initiating runtime, and the authenticated Link status
handler must respond for the owning device. A locally initiated CLI update may be confirmed by any authenticated paired-device workspace response on that host. `up_to_date` likewise requires exact
installed and active SHA equality. A timeout keeps its durable evidence and may be
reconciled by a later exact fresh-runtime response, but it never causes a second
blind restart.

Successful negotiated `sessions.history` replies may additionally carry:

```json
{"context":{"sessionId":"requested_session","available":true,"snapshot":{"version":1,"type":"session.context","sessionId":"requested_session","model":"host-model","contextUsed":17,"contextMax":100,"contextPercent":17,"compressions":0,"isCompacting":false,"updatedAt":1788000000}}}
```

The controller's successful profile-scoped result `payload.storedId` supplies the
canonical lookup coordinate; `context.sessionId` and its snapshot retain the
requested visible/stored coordinate. Agent correlation and known session bindings
must agree before lookup. This reads the adapter's existing live/cached current
context provider, not transcript token estimates or a new RPC. The existing
`session_context` validator bounds the snapshot and optional nonnegative
`inputTokens`, `outputTokens`, `cachedTokens`, and `totalTokens`. If current metrics
are absent, invalid, or unavailable, the envelope is
`{"sessionId":"requested_session","available":false,"snapshot":null}`. Failed,
unrelated, and unnegotiated requests do not invoke the provider.

Clients strictly validate optional context, correlate it to the pending history
request and host ownership, and deliver an available snapshot through the existing
session-context callback before resolving that history waiter. Explicit unavailable
publishes no new metric: last-known state stays last-known, never a synthetic zero.
Unnegotiated legacy replies remain accepted.

Invalid authenticated `workspace.request` payloads are quarantined in dispatcher
order. When `requestId` independently validates as 16..128 ASCII opaque characters
(`A-Z`, `a-z`, digits, `_`, `-`), the host queues an encrypted response:

```json
{"version":1,"type":"workspace.rejected","requestId":"request_example_0001","code":"unsupported_operation","message":"This host does not support that operation.","sentAt":1788000000}
```

The only other code is `invalid_request`, with fixed message
`This workspace request is invalid.` No payload, operation, or exception detail
is reflected. Missing/invalid correlation IDs are quarantined without an invented
request. Unfamiliar authenticated application payloads are also quarantined, so
receiving a newer response does not create a replay loop on this host.

Receipts happen in dispatcher order before rejection response delivery; a single
owned response worker holds at most 32 queued responses plus its current response,
with a total per-response deadline of 20 seconds plus the configured delivery
timeout. Overflow or delivery failure is logged with fixed text; clients may then
observe their ordinary request timeout, not a fabricated success. Receive work and
ACK processing never await this worker. Disconnect/stop cancels and drains its
owned tasks. Transport-lock acquisition polls cancellation rather than leaving a
blocked background lock-acquisition thread. A response already staged as an encrypted pending frame retains the
normal durable delivery obligation.

Skill mutation uses the Hermes profile-scoped skill APIs. Updates compare the
expected SHA-256 under the existing per-profile/skill lock. ZIP import keeps the
bounded archive limits, safe paths, exclusive creation, whole-bundle security
scan, and rollback on import failure. Session mutations retain profile scope and
the existing visible-to-stored-ID fallback. Pin state is included in session lists.

### Backpressure and permanent failures

Negotiated relay storage refusal has the exact control shape:

```json
{"version":1,"type":"backpressure","id":"frame_example_0001","sequence":1,"retryAfterMs":1000,"reason":"storage_limit"}
```

The host requires a positive integer sequence, valid opaque frame ID, enumerated
reason, and an integer delay of 100..30000 milliseconds. It acts only on the exact
current pending frame owned by this device/epoch. Stale controls do nothing.
One owned retry task uses the same live socket and identical frame/ciphertext;
backpressure neither advances nor discards pending state. Repeated controls do
not postpone an already scheduled retry. ACK, readiness reconciliation,
disconnect, and stop cancel obsolete retries. A caller's delivery deadline can
expire while a backpressured frame remains pending; it is not proof of failure or
permission to duplicate a business mutation. Receipts and controls keep flowing.
Legacy sockets continue using the relay's 1013 close-and-retry fallback.

Explicit device/epoch revocation codes in bounded HTTP 401/403 JSON responses,
and the relay's WebSocket authorization-revoked code 4003, stop automatic reconnect
and publish `authentication_error`. Generic 403 edge/nonce failures and policy
close 1008 do not establish revoked credentials and retain normal retry, as do
network/5xx/429 failures. Same-device replacement code 4000 remains terminal only
for the older runtime. No local device credentials or pending obligations are deleted.

## Loopdy Card version 1

`loopdy.card` version 1 is a display-only generated-interface document. The
generic `loopdy_render_card` tool validates an agent-supplied input against the
portable schema and cross-field policy, canonicalizes it, and adds these
renderer-owned fields:

```json
{
  "content_hash": "64 lowercase hexadecimal characters",
  "card_id": "first 32 characters of content_hash",
  "created_at": "RFC 3339 UTC timestamp",
  "origin": "live"
}
```

The content hash is SHA-256 over the canonical input before those fields are
added. The plugin rejects a mismatched hash before the result crosses a channel
or Link boundary. The existing `generative.ui` Link event carries the complete
card in its `card` field and retains the event, session, turn, tool call, agent,
and occurrence-time coordinates. The iOS client rejects invalid event
coordinates, schema/version pairs, trees, sources, and limits before rendering.

The v1 component type set is exactly `card`, `vstack`, `hstack`, `grid`, `text`,
`metric`, `badge`, `progress`, `chart`, `table`, `list`, `divider`, `spacer`, and
`image`. Values are literal bindings, JSON Pointer source bindings, or bounded
expressions. The only expression operations are `coalesce`, `add`, `subtract`,
`multiply`, `divide`, `percent_change`, `equal`, `not_equal`, `greater_than`,
`greater_than_or_equal`, `less_than`, `less_than_or_equal`, `and`, `or`, and
`not`. The document cannot carry scripts, HTML, arbitrary actions, POST
requests, credentials, supplied headers, remote images, or downloaded code.

Build 3 supports static Cards only. Every displayed value is embedded in the
document, `data_sources` must be empty, and the plugin rejects nonempty sources
with `live_data_unavailable`. The original Card crosses Loopdy Link once. The
iOS envelope validator independently rejects nonempty sources, and its
production Card data client fails closed. Opening a Card makes no third-party
Card data request. Source bindings and refresh behavior remain reserved for a
later security-reviewed release.

Template synchronization uses request-bound encrypted workspace operations
named exactly `cards.templates.list`, `cards.templates.install`, and
`cards.templates.remove`. Bundles contain metadata, an embedded card document,
a parameter schema, and a SHA-256 integrity value. Stores enforce profile and
account ownership, supported versions, hash validity, idempotent install,
upgrade ordering, and atomic replacement. Parameters can replace declared
literal slots only; they cannot alter component types, IDs, bindings,
operations, or renderer-owned fields. Template operations never use the notification relay,
and no production catalog origin is configured.

`loopdy.card` is additive. `loopdy.generative_ui` versions 1 and 2 continue to
decode and render through the existing legacy path, and
`loopdy_render_form` remains responsible for user input and request-bound
submissions. No envelope is silently converted between these schemas.

See [Loopdy Cards](docs/LOOPDY_CARDS.md) for the complete wire example,
finite component table, static delivery sequence, source limits, template
lifecycle, visible errors, and design credit.

Loopdy Cards credits Sameer Gupta's
[Generative UI DSL](https://github.com/sameergdogg/generative-ui) for the
constrained JSON-tree and fixed native component-catalog approach.
[Google A2UI](https://github.com/google/A2UI) and
[`json-render`](https://json-render.dev/) are related designs only. Loopdy does
not claim adoption, endorsement, API compatibility, or copied code from any of
these projects.

## Delivery providers

`relay` is the default. The host stores a bounded HTTPS origin, tenant identifier, and references to owner-controlled HMAC and P-256 signing-key material. It authenticates every request with a fresh nonce and revisioned idempotency coordinate. Ordinary alert content is encrypted end to end for the registered device; the relay cannot read the message. Live Activity updates carry only the sanitized state contract (phase, progress, counts, timestamps, and bounded identifiers). The relay does not receive Hermes transcripts, approval policy, credentials, local paths, or arbitrary tool arguments. Registration uses the base bundle topic only; the provider appends `.push-type.liveactivity` exactly once for ActivityKit delivery.

The native Swift client registers an ActivityKit push token for each active session and updates a
sanitized projection of reasoning, tool, and delegation progress. That state is not end-to-end
encrypted: the Worker can read it while constructing the ActivityKit APNs payload even when its
durable representation is encrypted at rest. The projection excludes prompts, tool arguments,
attachments, credentials, and complete model output.

`direct` is an advanced option for a self-hoster using their own signed Loopdy build. The plugin sends HTTP/2 requests directly to APNs. The operator configures the Apple team ID, key ID, topic, environment, and an owner-only local `.p8` path with `hermes loopdy configure-apns`. Key bytes and the full path are never returned by the API.

`managed` is retained for older Expo registrations and command-line compatibility. The authenticated
app registers an Expo push token with the user's Hermes plugin, which sends the shaped notification
to Expo Push Service for APNs delivery. It is not a user-facing choice in current Loopdy builds.

Relay device registration and sender-key acknowledgement establish the current device/configuration
generation. Delivery, Live Activity registration/update/revoke, tenant revoke, and tenant delete
are separate revisioned operations. A client accepts only the response status and coordinates
allowed for that route (`accepted`/`duplicate`, `revoked`/`duplicate`, or `deleted`/`duplicate` as
appropriate). Unknown transport outcomes are retried with the same canonical body and idempotency
coordinate; a response is never treated as success merely because the HTTP request completed.

After an Apple device has pinned Loopdy Link's current wake-relay key set and the private service
binding has recorded that acknowledgement, the app sends one account-encrypted `relay.ready`
control frame to its paired Hermes host. The frame contains only bounded relay coordinates,
recipient public-key material, topic/environment, lease, and the display name already protected by
Link transport. It contains no APNs token, account credential, or chat text. Version 1 of this
control is Link-wake readiness only: it is acknowledged by the host transport but can never create
a device in the host's optional notification-relay ledger. A future host-relay enrollment must be
explicitly scoped as `host_relay` and still pass the locally configured relay sender-key checks.
Neither control becomes a Hermes chat turn or pre-LLM input.

Local relay removal or replacement disables local relay routing and makes old registrations
untargetable until explicit re-registration. It does not implicitly perform a remote destructive
operation. A verified tenant revoke tombstones devices and ends their local Live Activities while
retaining configuration for an explicit delete; a verified tenant delete purges relay configuration
and local relay state. These transitions are local, transactional, and fail closed when the relay
response is missing, malformed, or has a route-incompatible status.

Switching providers requires a compatible device token. The plugin never falls back between providers.

## Hermes app API

Hermes mounts this router under `/api/plugins/loopdy/`. It inherits the dashboard's authentication
policy. Pairing belongs to the separate Loopdy Link service, so the Hermes plugin API deliberately
has no pairing or Link-secret route. Relay and Link credentials remain host-side and are not
returned by this API.

```text
GET    /capabilities
GET    /provider
PUT    /provider
GET    /devices
POST   /devices
DELETE /devices/{device_id}
PUT    /devices/{device_id}/preferences
POST   /test
GET    /events
GET    /events/{event_id}
GET    /approvals/{approval_id}
POST   /approvals/{approval_id}/respond
POST   /attachments/resolve
GET    /attachments/{attachment_id}?profile={profile}
```

## Agent attachments

`GET /capabilities` advertises `native_agent_attachments` and the attachment schema version. Clients resolve bounded assistant history pages with:

```json
{
  "profile": "default",
  "session_id": "session-123",
  "items": [
    {
      "id": "42",
      "text": "The report is ready.\nMEDIA:/local/path/report.pdf"
    }
  ]
}
```

The resolver passes text through Hermes' public `BasePlatformAdapter` extraction and delivery-policy methods. Consequently, `gateway.strict`, `gateway.media_delivery_allow_dirs`, `gateway.trust_recent_files`, and `gateway.trust_recent_files_seconds` remain authoritative. Loopdy does not duplicate private Hermes matchers or weaken path policy.

The response contains sanitized display text and opaque metadata only:

```json
{
  "schema_version": 1,
  "items": [
    {
      "id": "42",
      "text": "The report is ready.",
      "attachments": [
        {
          "id": "0123456789abcdef0123456789abcdef",
          "kind": "file",
          "name": "report.pdf",
          "mime_type": "application/pdf",
          "size": 1234
        }
      ]
    }
  ]
}
```

The download route requires the same dashboard authentication as every other plugin route and enforces profile isolation. The client sends credentials in headers or cookies, never in the URL, and disables redirects for token-bearing requests. Approved bytes are retained in a durable profile-scoped cache so normal history reopening does not depend on the original file remaining present. Local paths are never included in response bodies, attachment IDs, filenames, or download URLs.

Resolver limits are 200 items, 100,000 aggregate UTF-8 text bytes, 20 attachments per item, 25 MiB per artifact, and 240 UTF-8 bytes per filename. The durable cache is capped per profile at 500 artifacts or 250 MiB, whichever is reached first; oldest artifacts and their cached message projection are evicted together so a surviving source can be resolved again. Missing, denied, stale, malformed, and oversized references produce no attachment.

Managed registration uses:

```json
{
  "device_id": "phone-123",
  "provider": "managed",
  "push_token": "ExponentPushToken[fixture-phone]",
  "token_environment": "production",
  "label": "iPhone",
  "groups": ["personal"]
}
```

Direct registration uses the same shape with `provider: "direct"` and a native APNs token. Device responses contain a short token fingerprint and never contain the token.

Preferences include notification enablement, event toggles, `automatic`, `minimal`, or `detailed` content, lock-screen previews, priority sound, and optional quiet hours. A new device with no explicit `enabled_types` uses the current documented event defaults. Once `enabled_types` is stored, registration and partial preference updates preserve that exact selection; newly introduced event types are not silently enabled. Preference updates are version 2, and omitted fields retain their stored values.

Approval responses accept `once`, `session`, `always`, or `deny` plus the immutable request digest. The client may submit only a scope present in the request's authoritative `allowed_choices`; the pending record must exist, remain unexpired and unanswered, offer the choice, and match that digest.

## Native channel and push envelope

Hermes registers `loopdy` as an outbound platform with `all`, `device:<id>`, and `group:<id>` targets. Native sends, scheduled tasks, cron, lifecycle hooks, and host automation all enter the same local event ledger. Proactive delivery does not require an active mobile session.

The push data envelope contains only schema version, event ID, event type, deep link, and an approval ID when applicable. Display title and body follow the user's detail and lock-screen preferences. Tool arguments, credentials, full provider tokens, and authoritative approval policy never enter push data.

### Live Activity session correlation

Hermes exposes a transient JSON-RPC handle and a durable session key when `session.create`
succeeds. Loopdy plugin hooks receive the agent's durable `session_id`, which is the native
bridge's `sessionID` (`stored_session_id` in the create response). The response's transient
`session_id` is carried separately as native `liveSessionID` for RPC transport. ActivityKit's
`activityID` is a local Apple delivery identifier and is not emitted by Hermes.

Relay registration and every relay update therefore use the one canonical opaque reference for
the plugin-visible Hermes session key:

```text
session_ref = base64url_without_padding(SHA-256(UTF-8(Hermes plugin session_id)))
```

The raw Hermes session ID and the ActivityKit ID are never sent as the relay's routing reference.
The shared fixture at `packages/contracts/fixtures/relay-session-coordinate-v1.json` is consumed
by the native-source and Python contract tests so this mapping cannot drift silently.

Supported event types are:

- `attention.required`
- `approval.required`
- `session.completed`
- `session.failed`
- `delegation.started`
- `delegation.updated`
- `delegation.completed`
- `task.updated`
- `job.completed`
- `job.failed`
- `channel.message`
