# Loopdy plugin security

## Trust boundaries

- Hermes is authoritative for tool policy, approval scope, sessions, tasks, and detailed event records.
- Loopdy Link uses one Durable Object per minimal passkey account to coordinate multiple revocable devices. It stores opaque account and device coordinates, public keys, authorization epochs, encrypted device names, encrypted frames, bounded delivery state, and APNs routing material. It does not store email addresses, passwords, phone numbers, profile details, Hermes credentials, or chat plaintext.
- Phone, tablet, and Hermes-host devices generate their own signing and agreement keys. The host commits its flow, device coordinate, signing key, and agreement key into the QR payload and a separately displayed manual fingerprint. The app verifies that commitment before releasing the account key. Deleting a device advances authorization state so the removed identity can no longer connect.
- Chat frames are encrypted on the sending device with the account key, device signed for transport admission, replay protected, and decrypted only by paired account devices. The Link service is not a generic proxy and cannot invoke arbitrary Hermes APIs.
- The authenticated Loopdy app registers and revokes only its own notification device records.
- Managed delivery trusts Expo's push service and Apple APNs for transport.
- Direct delivery trusts Apple APNs and keeps the user's Apple signing key on their Hermes host.
- Relay mode uses an optional authenticated HTTPS relay endpoint. D1 stores encrypted APNs tokens,
  encrypted pending payloads, and bounded routing/operation metadata needed to forward
  notifications; it is not authoritative for Hermes sessions, approvals, or history. Ordinary
  alert copy is end-to-end encrypted. The optional Live Activity contract is not end-to-end
  encrypted: sanitized state is visible to the Worker while it constructs an ActivityKit payload
  for APNs. The native Swift client registers and updates this bounded state. Prompts, tool
  arguments, attachments, credentials, and complete model output are excluded. The relay is not
  zero-knowledge for this ActivityKit delivery path.
- The encrypted paired socket can carry bounded tool arguments/results for an explicit in-chat
  detail view; the Live Activity/APNs projection strips those fields before relay delivery.
- The local plugin also maintains an owner-only notification database containing device
  registrations, event summaries, delivery state, and bounded retry records.
- Lock-screen surfaces can reveal content, so users control preview detail independently for each device.
- The encrypted Project manager exposes only explicit Hermes Project mutations. Archive marks the
  Project registration archived and never deletes its folders or data. Folder suggestions return
  directory names and canonical paths only, with strict page bounds; files, file contents, hidden
  build directories, traversal paths, control characters, and symlink children are excluded. The
  host process's normal filesystem read/search permissions remain authoritative.

## Generated media

Generated media resolution accepts only profile, stored-session, turn, and
exact tool-call coordinates, never a client-supplied path or URL. It reads that
profile's stored Hermes history, verifies an unambiguous supported generation
call/result, and reuses Hermes' media-delivery path policy and the existing
profile-scoped attachment cache. The plugin-owned identity ledger retains at
most 512 recent call coordinates; it contains no prompts, results, or media bytes.

Host-to-device artifacts are bounded to 25 MiB each and transferred in at most
64 KiB chunks. Generated results expose at most eight artifacts and 32 MiB total.
Phone-upload limits remain 8 MiB/file and 24 MiB/message. Oversize diagnostics
retain MIME types internally, not source paths; wire metadata contains opaque
attachment IDs, safe filenames, MIME types and byte counts. See
[Generated media](docs/GENERATED_MEDIA.md) for states and ownership details.

## Workspace Files grants

Workspace Files is a separate read-only plugin feature, exposed through the existing authenticated host API and a host CLI. Explicit local grants bind opaque IDs to pinned root directories; there is no automatic grant from Hermes Projects, no remote grant endpoint, and no private Project/session API dependency. Authenticated host API clients can inspect the grants in that host/profile; this is not yet a per-device encrypted Link permission. Existing Link behavior is unchanged.

The implementation requires secure POSIX descriptor-relative traversal and refuses unsupported hosts. It rejects traversal, symlinks, unsafe hard links, special files and sensitive control/credential paths; it scans each bounded file for known credential patterns before returning any chunk. Pattern scanning is not universal secret detection, especially for opaque binary/compressed files. A host operator must grant only an appropriate project directory. Root replacement, stale versions and revocation fail closed; already delivered content cannot be recalled. See [Workspace Files](docs/WORKSPACE_FILES.md) for bounds, authentication, pagination and deferred client integration.

## Secrets and local state

The owner-only SQLite database stores device push tokens, provider metadata, preferences, event summaries, delivery receipts, and pending approval bindings. Device tokens are addresses, but they are still treated as secrets. API and CLI diagnostics expose only a short SHA-256 fingerprint.

Loopdy Link host credentials are written through Hermes' configuration writer. They include an opaque device ID, authorization epoch, P-256 signing key, X25519 agreement key, and the account AEAD key. CLI status is deliberately redacted and never returns private or account-key material. Mobile Link credentials are kept in the iOS Keychain; the app does not store a separate Hermes gateway origin or token.

Direct mode stores the configured APNs key path, team ID, key ID, topic, and environment. The private `.p8` file stays outside this public repository and must be owner-readable only. The plugin validates that it is a P-256 private key before activating direct mode. Notification provider state never stores a Hermes gateway password or token.

## Network behavior

- Managed delivery contacts only Expo's HTTPS push endpoints and refuses redirects.
- Direct delivery contacts Apple's production or sandbox HTTP/2 APNs endpoint selected by host configuration.
- Relay delivery contacts only the configured HTTPS relay origin; the relay then contacts APNs.
- Loopdy Link pairing contacts only the configured HTTPS Link origin. After pairing, the host maintains an outbound WSS connection to that same origin; no inbound listener or OS-specific service manager is required.
- Requests use bounded timeouts and bounded response bodies.
- Retryable operations use their provider-specific bounded journal. Relay Queue delivery permits no more than two retries; local direct/relay recovery rows become terminal at their compiled attempt cap.
- Invalid provider tokens are revoked locally.
- Event IDs and per-device delivery rows provide idempotency.
- Quiet hours use each device's configured IANA time zone.

## Notification content

Users can choose automatic, minimal, or detailed notifications. Disabling lock-screen previews forces minimal presentation. Approval pushes contain opaque lookup identifiers and a safe summary, never tool arguments, prompts, credentials, or transcript text. The app requests authoritative details through the encrypted, request-bound Loopdy Link workspace contract.

Managed relay alerts use a device-generated P-256 recipient key, relay sender-key pinning, P-256
signatures, ECDH/HKDF, and AES-GCM. The app and its Notification Service Extension share only the
recipient private key and pinned public sender keys through their signed Keychain access group. The
extension accepts the exact versioned envelope and authenticated metadata, rejects unknown or stale
sender keys and malformed plaintext, and leaves the generic fallback notification unchanged on any
verification or decryption failure.

The account-encrypted `relay.ready` device control carries no APNs token or account secret. It is
accepted only from the same verified Link device and is never delivered to Hermes as user text or
model context. Link-wake readiness is deliberately separate from the host's optional relay tenant
and cannot create a host relay route. Only an explicitly host-scoped control that matches the
host's local relay sender-key generation may update that separate delivery ledger.

## Approval safety

- Plugin installation does not activate the approval transport.
- The operator must explicitly configure `security.approval.transport: loopdy`.
- `transport_fallback: deny` is recommended.
- The mobile flow preserves only the `once`, `session`, `always`, and `deny` choices explicitly offered by Hermes; it never adds a broader scope.
- Responses are bound to the Hermes request ID and immutable digest.
- Expired, repeated, missing, malformed, or mismatched responses fail closed.

## Revocation

Signing out of Loopdy performs a best-effort authenticated device revocation before local credentials are removed. A device can also be revoked from Loopdy Settings or with the authenticated plugin API. Switching providers does not expose or transmit the other provider's token.

Deleting the Loopdy account requires a fresh passkey assertion. The Link service revokes push and
Live Activity routes, deletes the passkey account and device directory rows, closes active sockets,
and purges the per-account Durable Object. The app clears its local account files, preferences,
notification keys, credentials, and in-memory models only after remote deletion succeeds.

Report vulnerabilities according to the repository's root `SECURITY.md`.

## Wiki connection authority

Explicit authenticated `wiki.connect` may create only a new read-only folder grant scoped to the verified initiating device, selected profile, current host pairing authority, pinned root inode/device, and fresh generation. It does not accept caller-selected authority, grant IDs or writable mode, overwrite host grants, or adopt registrations across authority boundaries. Unauthorized overlapping roots are rejected to prevent parent/child bypass. Host administration retains policy modification and revoke. `wiki.resolve` and directory suggestions remain non-mutating.

New registrations reject traversal, symlink ancestors, system/credential/control directories, configured Hermes home and Wiki state (including enclosing folders). An existing host-approved Wiki subfolder inside configured Hermes home may be reconnected only after all overlapping grants pass authority/profile/device checks, exactly one matching grant is found, and its pinned directory identity and generation are revalidated. This never creates or modifies a grant, and does not relax the home-directory, system/credential-path, symlink, or Wiki-state exclusions. Hosts without the required descriptor-relative traversal omit Wiki capability advertisement and operations. Cold state initialization walks descriptors with no symlink following, creates missing directories privately, and never chmods foreign directories. Optional absolute root metadata is authorized encrypted account content; selected references disclose their real source path alongside the requested text, not in relay-readable metadata.
