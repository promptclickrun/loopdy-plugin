# Loopdy for Hermes

Loopdy is a native Hermes platform for the Loopdy mobile app. It provides encrypted Loopdy Link chat, verified device/person context, proactive notifications, lifecycle events, approval transport, attachments, and Generative UI. Hermes remains authoritative for agents, sessions, scheduled tasks, policy, event details, and transcripts.

Loopdy Link is the app's reliable chat transport. The Hermes host opens one outbound WebSocket to `https://link.loopdy.app`; the app and host encrypt chat frames with the account key before they reach the service. Pairing is proof-of-possession based and gives each host its own revocable device identity. The cloud service cannot read chat plaintext.

The same paired Loopdy Link connection carries a fixed, versioned set of encrypted workspace operations for agents, Hermes Projects, sessions, scheduled tasks, per-agent defaults, approvals, events, and attachments. It is not an arbitrary HTTP proxy: every operation is explicitly allowlisted, bounded, validated, and handled through Hermes-owned Project, profile, session, cron, policy, and plugin surfaces. Agent-default reads use Hermes' native profile-scoped `config.get` and `model.options` methods, with compatibility fallback for older Hermes releases. Project creation registers one existing remote folder, archive removes only the Project registration from active catalogs, and folder suggestions return bounded directory coordinates without file contents. The app never needs a Hermes gateway origin or token after pairing.

Scheduled-task output choices come from Hermes' own cron delivery-target catalog. Loopdy accepts enabled catalog targets or a validated canonical `platform:chat_id[:thread]` value and sends that value through the official cron `deliver` field.

Loopdy exposes two delivery choices:

- `relay`, the default: a managed HTTPS relay forwards encrypted alerts to APNs. The relay is an
  authenticated delivery service only; Hermes remains authoritative for sessions, policy, and
  the local notification ledger.
- `direct`: the Hermes host signs requests with the user's Apple developer key and sends them directly to APNs.

The older `managed` Expo provider remains accepted for stored registrations and command-line
compatibility, but the app does not offer it for new selection.

All modes support proactive messages even when no chat session is active.

## Install

Install and enable the plugin in the active Hermes profile:

```bash
hermes plugins install promptclickrun/loopdy-plugin --enable
hermes gateway restart
```

For a committed local checkout:

macOS or Linux shell:

```bash
hermes plugins install "file://$PWD" --enable
hermes gateway restart
```

Windows PowerShell:

```powershell
$repo = [System.Uri]::new((Get-Location).Path).AbsoluteUri
hermes plugins install "$repo" --enable
hermes gateway restart
```

Hermes' file installer reads Git content, so local plugin changes must be committed first.

The plugin supports Hermes on Linux, macOS, and Windows. It uses Hermes' own
cross-platform Python dependencies and profile/config writers, stores data under
the active Hermes home directory, and opens outbound HTTPS/WebSocket connections
only. It has no launchd, systemd, Windows Service, shell-script, or inbound-port
requirement. Long-running process management remains the responsibility of the
normal Hermes installation on that operating system.

Create or sign in to the minimal passkey-backed Loopdy account in the app. Then start host pairing:

```bash
hermes loopdy link pair
```

The command prints a short-lived code, pairing URL, and separate 16-character host-key verification code. In Loopdy, open **Settings → Loopdy Link → Pair a Device**. QR pairing carries the full host-key commitment; manual pairing requires both the six-character code and the separate verification code. The app recomputes that commitment from the inspected host signing and agreement keys before it releases the account key. Pairing also reconciles APNs registration for that iPhone or iPad and pins Loopdy Link's wake-relay signing keys. That account-scoped wake channel is independent of the host's optional notification-relay tenant, so no shared relay credential is installed on Hermes. After storing the host credentials, the pairing command asks the official Hermes lifecycle command to activate the gateway automatically. No additional app or gateway configuration is required.

These commands are optional diagnostics if connectivity does not become ready:

```bash
hermes loopdy link status
hermes loopdy status
```

Pair each additional Hermes host independently. All phone, tablet, and host devices can be named, renamed, inspected, and revoked from the same Loopdy account.

Signed Loopdy builds include a Notification Service Extension. Ordinary alert copy arrives as an
encrypted payload and is shown only after the extension validates the pinned relay sender key,
signature, recipient key, authenticated metadata, and bounded plaintext. Verification failure keeps
the generic fallback notification and never exposes unverified content.

Verify the native channel:

```bash
hermes loopdy status
hermes loopdy test --target all
```

## Direct APNs

Direct mode is optional. It requires an Apple Developer account, a signed app build for the configured bundle ID, and a P-256 APNs token key stored on the Hermes host. The key file must be owner-readable only.

The values below are placeholders. Use identifiers from your own Apple Developer account and never commit an APNs key.

```bash
chmod 600 /private/path/AuthKey_KEYID12345.p8
hermes loopdy configure-apns \
  --team-id TEAMID1234 \
  --key-id KEYID12345 \
  --topic app.example.loopdy \
  --environment production \
  --key-path /private/path/AuthKey_KEYID12345.p8
hermes loopdy status
hermes loopdy test --target all
```

Select direct delivery after configuration with:

```bash
hermes loopdy provider direct
```

## Relay

Relay mode is the app default and is designed for hosts that cannot receive inbound connections. Configure
the relay origin, tenant, and references to owner-controlled HMAC/signing-key material in the active
Hermes profile. Secret references are resolved on the Hermes host and are never sent to the mobile
client or written to relay request bodies. Plugin release `2.3.0` carries Link and relay wire version `1`;
the two version layers are independent. An authenticated encrypted `user.message` may include the
optional wire-version-1 `behavior` value `steer`, `queue`, or `interrupt`. The adapter maps those values
to Hermes' registered platform controls, preserves normal approval and clarification interception, and
uses the normal message path when the field is absent. The relay uses authenticated HTTPS,
revisioned/idempotent device and tenant operations, and encrypted ordinary alert payloads. Live
Activity state is deliberately sanitized and contains no message text, credentials, or filesystem
paths.

Workspace selection follows Hermes' native lifecycle semantics. A new Loopdy chat seeds its selected
Project path before the first turn without creating an empty stored session. Moving an existing chat
updates its persisted CWD, updates the live terminal/file-tool CWD immediately, and invalidates the
cached agent so the next turn rebuilds from the moved Project context. A tool call already in progress
finishes in the directory where it started, matching `session.workspace.move`.

The native Swift client starts one ActivityKit activity per active session, registers its push
token through Loopdy Link, projects bounded reasoning/tool/delegation progress, and revokes the
activity when the final response settles or the account boundary closes. Sanitized state is
server-readable while the Worker builds the APNs payload; prompts, tool arguments, attachments,
credentials, and complete model output are excluded.

Relay registration, acknowledgement, revocation, delivery, and Live Activity operations are
authenticated, origin-bound, and fail closed on invalid revisions or response coordinates. A relay
response is accepted only for the operation that created it. Removing or replacing local relay
configuration disables existing local relay routing until devices are explicitly registered for the
current configuration; it does not silently revoke remote tenant state. Explicit tenant revoke and
delete operations update local tombstones only after a valid relay response.
Use the base app bundle identifier as the registration topic; the provider appends
`.push-type.liveactivity` exactly once when sending a Live Activity update.

The relay stores only the minimum encrypted delivery data needed to forward a request and does not
replace Hermes history or approval storage. Ordinary alert copy is end-to-end encrypted, while
sanitized Live Activity state is visible to the Worker during APNs submission. See
[PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md), and the repository
[security and privacy inventory](docs/SECURITY_AND_PRIVACY.md) for the complete public trust
boundary and data-flow description.

Remove the saved direct configuration with:

```bash
hermes loopdy remove-apns --yes
```

## Native channel and proactive messages

Loopdy registers a normal Hermes platform named `loopdy` with these targets:

- `all`
- `device:<id>`
- `group:<id>`

Examples:

```bash
hermes send --to loopdy:all "Task completed"
hermes send --to loopdy:device:phone-123 "Review requested"
```

Scheduled tasks can use `deliver="loopdy"`. `LOOPDY_HOME_TARGET` selects the default target and defaults to `all`. The standalone sender uses the same local device registry, provider configuration, preferences, quiet hours, and delivery ledger, so it does not require a live chat session.

### A. Inline card in the active chat

When a card answers the current Loopdy conversation, call the renderer on that
active conversation response path. The validated result returns to the open
chat as part of its turn. Do not use the notification channel just to answer the current chat, and do not target `loopdy:all` or a device merely to render it.

### B. Proactive or scheduled card in Agent Inbox/Home

For an ordinary proactive channel message or a scheduled task, explicitly
target the `loopdy` platform. No script or extra API is needed: call one
registered `loopdy_render_*` tool and make its exact validated returned envelope
the complete delivered content, with no Markdown fence or additional prose.
Hermes' official channel boundary passes the adapter only that final content and
normal metadata such as cron `job_id`; an earlier inline renderer result does not auto-forward to the channel. The adapter revalidates complete envelopes before
persisting and pushing cards, while invalid or missing cards safely fall back to
text. Never script or reconstruct an envelope; forward the exact official
renderer return value. The installed `loopdy:generative-ui` skill contains both
pathways, their decision rule, and scheduled/ordinary channel examples.

## Native Generative UI

The plugin registers `loopdy_render_summary`, `loopdy_render_metrics`, `loopdy_render_list`, `loopdy_render_timeline`, and the typed v2 renderers as first-class Hermes model tools. When the exact renderer is visible in the current tool list, agents call it directly. When Hermes has hidden it through progressive disclosure, agents use the official progressive-disclosure bridge—`tool_search`, `tool_describe`, and `tool_call`—to find and invoke that exact renderer. A visible renderer should not be needlessly routed through the bridge, and a different tool must never substitute for it.

The read-only namespaced skill `loopdy:generative-ui` documents selection guidance and bounded payload examples. Hermes can load it with `skill_view("loopdy:generative-ui")`; installation does not copy or modify the user's ordinary skill directory.

### Loopdy Cards

`loopdy_render_card` accepts one display-only `loopdy.card` version 1 document
built from the finite native component catalog. Build 3 supports static Cards
only: all displayed values must be embedded in the payload and `data_sources`
must be empty. The plugin rejects live sources, unknown fields, components,
bindings, expressions, formats, broken trees, and bounded-size violations. It
canonicalizes a valid input, adds `content_hash`, `card_id`, `created_at`, and
`origin`, then returns the exact result through the normal generated-interface
path. Do not reconstruct the renderer result or mix it with prose.

The app receives the original static Card once through encrypted Loopdy Link,
validates it again, and renders its embedded values natively. Opening a Card
makes no third-party Card data request. Live Card refresh remains reserved for a
later security-reviewed release.

Template bundles remain declarative data. Encrypted workspace operations
`cards.templates.list`, `cards.templates.install`, and
`cards.templates.remove` synchronize reviewed installs between the app and the
profile-scoped plugin store. The generic template tools are
`loopdy_search_card_templates`, `loopdy_get_card_template`, and
`loopdy_render_card_template`; all rendered output still passes through
`loopdy_render_card`. Templates cannot install native code or expand the v1
component catalog. No production template catalog URL is configured.

See the repository [Loopdy Cards guide](docs/LOOPDY_CARDS.md) and the
[wire protocol](PROTOCOL.md#loopdy-card-version-1) for the complete example,
component table, static-data policy, visible error states, lifecycle, and legacy
compatibility.

Loopdy Cards credits Sameer Gupta's
[Generative UI DSL](https://github.com/sameergdogg/generative-ui) for the
constrained JSON-tree and fixed native component-catalog approach.
[Google A2UI](https://github.com/google/A2UI) and
[`json-render`](https://json-render.dev/) are related designs only. Loopdy does
not claim adoption, endorsement, API compatibility, or copied code from any of
these projects.

## Native agent attachments

Loopdy provides Hermes-parity delivery for assistant-generated images and files. The mobile client resolves assistant history through the authenticated plugin API, displays images inline, and presents other artifacts as named file cards. Downloads use the existing dashboard authentication headers or cookies with redirects disabled for token-bearing requests. Gateway credentials and local source paths are never placed in attachment URLs or returned to the client.

Hermes native `send_image_file`, `send_document`, `send_video`, and `send_voice` callbacks are projected
through the same policy-backed resolver. This covers media dispatched separately after streamed text;
the iOS client resolves both request-owned finals and later unsolicited attachment messages before
rendering them.

Resolution delegates extraction, extension routing, and path authorization to Hermes' public `BasePlatformAdapter` media API. The active Hermes settings remain authoritative, including `gateway.strict`, `gateway.media_delivery_allow_dirs`, `gateway.trust_recent_files`, and `gateway.trust_recent_files_seconds`. Their runtime environment equivalents (`HERMES_MEDIA_DELIVERY_STRICT`, `HERMES_MEDIA_ALLOW_DIRS`, `HERMES_MEDIA_TRUST_RECENT_FILES`, and `HERMES_MEDIA_TRUST_RECENT_SECONDS`) are honored by the same adapter.

Approved artifacts are copied into a profile-scoped durable cache and addressed by opaque IDs. This lets reopened sessions retrieve attachments without retaining or disclosing the original filesystem path. Requests are bounded to 200 message items, 100,000 aggregate UTF-8 text bytes, 20 attachments per item, 25 MiB per artifact, and 240 UTF-8 bytes per display filename. Each profile cache is capped at 500 artifacts or 250 MiB and evicts the oldest entries first. Missing, denied, stale, malformed, and oversized references fail closed.

## Approvals

Installation does not activate Loopdy as an approval transport. To opt in, configure the active Hermes profile:

```yaml
security:
  approval:
    transport: loopdy
    transport_fallback: deny
```

Restart the process that runs Hermes sessions after changing configuration. Loopdy preserves the exact approval scopes offered by Hermes: `once`, `session`, `always`, and `deny`. The app never invents a scope that Hermes omitted. Missing, expired, duplicate, unoffered, or digest-mismatched responses fail closed.

## Commands

```text
hermes loopdy status
hermes loopdy link pair [--base-url https://link.loopdy.app]
hermes loopdy link status
hermes loopdy link unpair --yes
hermes loopdy provider [relay|direct]
hermes loopdy configure-apns --team-id ID --key-id ID --topic BUNDLE_ID --environment production|sandbox --key-path PATH
hermes loopdy remove-apns --yes
hermes loopdy recover-terminal-relay-registration --yes
hermes loopdy test [--target TARGET]
```

`status` reports only token fingerprints and the APNs key filename. `link status` reports only the public origin, opaque device ID, authorization epoch, and connection state. Neither command prints device tokens, account keys, private keys, private-key paths, or key contents.

`recover-terminal-relay-registration --yes` is a bounded, local-only repair for an exact legacy
terminal registration conflict that already has a stored relay response. It revalidates the current
relay generation, request/response coordinates, and local sender-key pins before applying that
response. It never contacts the relay and prints aggregate counts only.

## Authenticated app API

Hermes mounts these routes under its normal dashboard authentication policy:

```text
GET    /api/plugins/loopdy/capabilities
GET    /api/plugins/loopdy/provider
PUT    /api/plugins/loopdy/provider
GET    /api/plugins/loopdy/devices
POST   /api/plugins/loopdy/devices
DELETE /api/plugins/loopdy/devices/{device_id}
PUT    /api/plugins/loopdy/devices/{device_id}/preferences
POST   /api/plugins/loopdy/test
GET    /api/plugins/loopdy/events
GET    /api/plugins/loopdy/events/{event_id}
GET    /api/plugins/loopdy/approvals/{approval_id}
POST   /api/plugins/loopdy/approvals/{approval_id}/respond
POST   /api/plugins/loopdy/attachments/resolve
GET    /api/plugins/loopdy/attachments/{attachment_id}?profile={profile}
```

See [PROTOCOL.md](PROTOCOL.md) for request contracts and [SECURITY.md](SECURITY.md) for trust boundaries.

## Development

Run the deterministic offline suite with the Python environment bundled with Hermes:

```bash
PYTHONPATH=/path/to/hermes-agent:plugins/loopdy \
  /path/to/hermes-agent/venv/bin/python \
  -m unittest discover -s plugins/loopdy/tests -v

hermes plugins doctor plugins/loopdy --ci
```
