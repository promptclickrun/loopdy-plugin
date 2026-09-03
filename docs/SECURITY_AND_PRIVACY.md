# Security and privacy

This document describes the technical behavior of the current implementation.
It is not legal advice and does not replace a jurisdiction-specific privacy
policy, App Store disclosure review, or independent security audit.

## 1. Security goals

Loopdy aims to:

- Keep message content unreadable to the Cloudflare routing layer.
- Authenticate every authorized endpoint independently.
- Make endpoint revocation enforceable without rotating every other device.
- Prevent replay, cross-session substitution, malformed payloads, and stale
  callbacks from becoming trusted application state.
- Keep private keys and content keys out of source code and ordinary
  preferences.
- Deliver notification text only after cryptographic authentication and
  decryption on the recipient device.
- Minimize durable cloud data and separate account routing from APNs delivery.

## 2. Cryptographic design

### Account content key

The app creates a random account content key on the device. Message and workspace
payloads are authenticated and encrypted with AES-GCM before they enter the
Loopdy Link routing plane.

During account registration, the app uses a passkey PRF result to wrap the
account content key. The cloud stores the resulting encrypted envelope, not the
plaintext account key. On sign-in, the passkey PRF result unwraps the key on the
device.

### Device authentication

Each device creates its own P-256 signing key. The private key remains in the
device Keychain; the public key is registered with the account service.
Authenticated requests include freshness and replay-protection material and are
verified against the device's current authorization epoch.

Device-friendly names are encrypted with the account content key before cloud
storage.

### Host pairing

Pairing uses a short-lived human-readable challenge. Approval transfers the
account content key to the new Hermes host through an ephemeral Curve25519 key
agreement, HKDF-derived wrapping key, and authenticated encryption. The pairing
code is not a reusable credential and does not contain a private key.

The host locally commits to the pairing flow, device coordinate, signing public
key, and agreement public key. QR pairing carries the complete SHA-256
commitment. Manual pairing requires a separately displayed 16-character
fingerprint derived from that commitment. The app derives the commitment again
from the server-inspected keys and refuses to release the account key if it does
not match. The plugin ignores any pairing URL supplied by the service and
constructs the verified URL from its own keys.

### Link frames

WebSocket frames contain routing and sequencing metadata plus AES-GCM
ciphertext. The account/link Worker and Durable Object route this envelope
without decrypting the content.

The endpoints enforce monotonic sequence handling, acknowledgements, duplicate
recognition, request/session matching, and bounded decoding.

### Encrypted alerts

Each mobile device owns a notification recipient key. Alert encryption uses an
ephemeral key agreement, HKDF, and AES-GCM. The relay signs the complete
envelope. The device validates a bounded, validity-windowed sender-key set
provided during authenticated push registration.

Notification content is rendered only after signature, freshness, recipient,
and authenticated-decryption checks succeed.

The account service provisions the sender-key set. No independent out-of-band
transparency or continuity mechanism anchors it. This protects against
modification in APNs transit and relay storage, while the account service
remains in the notification trust boundary.

## 3. Trust model

### Trusted with plaintext

- The user's unlocked iOS device
- Each explicitly authorized Hermes host
- AI or tool providers configured by that Hermes host, for data required to
  perform the user's request

### Not trusted with plaintext message content

- Loopdy's Cloudflare routing Worker
- The per-account Durable Object
- The notification relay database
- The asynchronous APNs delivery queue
- Apple Push Notification service for encrypted alert bodies

### Loopdy Card data sources

Build 3 accepts static `loopdy.card` documents only. Delivered Cards must have an
empty `data_sources` array, and the production client does not perform Card data
fetches. Live third-party data sources remain reserved for a later security-reviewed
release. The dormant parser and network-policy code are not production-reachable in
this build.

### Important limitation

End-to-end encryption protects content while it passes through Loopdy's cloud
services. It cannot protect content on a compromised authorized device or
Hermes host. A configured provider may receive plaintext needed for the request.
Screen capture and visible Lock Screen content can also expose information.

It also does not hide traffic metadata such as IP address, timing, connection
duration, ciphertext size, or device-routing relationships from infrastructure
providers.

The routing service can still delay, suppress, or replay-invalid pairing
traffic, but it cannot substitute a different host key without failing the QR
commitment or separately displayed manual verification code.

## 4. Data inventory

| Data | On iOS device | Loopdy Cloudflare | Hermes / providers |
|---|---|---|---|
| Messages and replies | Local session cache | Transient ciphertext only | Plaintext as needed to run the agent |
| Attachments | Local session cache; memory during upload | Transient ciphertext only | Plaintext as needed to process the request |
| Voice audio | Memory during on-device recognition | Not sent by Loopdy | Not sent as raw microphone audio |
| Voice transcript | Local session cache | Transient ciphertext only | Plaintext as the user request |
| Synthesized speech audio | Memory during playback | Transient ciphertext only | Generated by the configured voice service |
| Agent instructions/settings | Local presentation cache | Transient ciphertext for workspace operations | Stored according to Hermes configuration |
| Device private/signing keys | Keychain | Never | Only keys generated by that endpoint |
| Account content key | Keychain | Encrypted envelope only | Present on authorized endpoints |
| Passkey biometric data | Apple authentication system | Never | Never |
| Passkey public credential | System-managed locally | Durable public metadata | Not required |
| Device name | Local | Authenticated ciphertext | Readable by authorized account endpoints |
| Device/public-key metadata | Local | Durable operational metadata | Used to authorize endpoints |
| APNs token | System/app memory and Keychain-related state | Encrypted at rest in relay storage | Not required |
| Alert title/body | Device after decryption | Encrypted payload | Created by the authorized source |
| Live Activity state | ActivityKit | Bounded state, encrypted at rest but readable during relay delivery and by Apple | Created from agent activity |
| Static Card document and embedded values | Local transcript cache | Transient ciphertext only | Generated and validated on the authorized Hermes host |
| Live Card source URL, response, and request metadata | Not accepted in build 3 | Not accepted in build 3 | Not accepted in build 3 |
| Preferences | UserDefaults | Not uploaded as preferences | Not required |
| Avatars | App sandbox | Filename metadata only through workspace flows | Image upload is not part of the current directory path |

## 5. Local storage

### Keychain

Private credentials use non-synchronizing, device-only Keychain items. They are
available after the first device unlock so background networking and
notification processing can operate.

Signing out attempts a signed request to revoke this device and its push/Live
Activity authorization, then deletes Loopdy Link runtime credentials,
notification recipient keys, sender-key pins, account-scoped defaults, local
content files, and all account-scoped in-memory state. Local erasure still runs
if the remote revocation is unavailable, and the app surfaces that revocation
could not be confirmed. Uninstall behavior alone should not be treated as
remote revocation.

The app stores the account and signing keys as software keys in device-only
Keychain items rather than as Secure Enclave private-key objects. A sufficiently
privileged compromise after the first unlock may expose them.

### App sandbox

The app stores readable session caches, drafts, attachments, Bot Mode history,
agent metadata, settings, and avatars in its private container. The JSON
repositories are versioned and crash-safe but do not add a separate
application-level encryption layer. JSON and attachment directories explicitly
use complete-until-first-user-authentication protection so background Link and
notification reconciliation can continue after the first unlock. Avatar files
and directories use complete protection and remain unavailable while locked.
Protected files and directories, including Link's pending encrypted transport
state and corruption recovery backups, are explicitly excluded from device
backups.

The pending encrypted Link frame and its sequence/acknowledgement state are
stored in protected Application Support JSON rather than backup-eligible
UserDefaults. Existing per-device UserDefaults snapshots migrate to this file
before their legacy keys are removed.

Anyone who can unlock or compromise the device may be able to read this local
content.

## 6. Cloud retention

The current Cloudflare deployment stores durable identity and delivery metadata
but no readable chat-session database.

- Passkey public records, account coordinates, and active device public keys
  remain while the account/device remains authorized.
- The service stores only hashes of access tokens.
- Authentication challenges and access sessions become invalid after expiry or
  consumption; immediate physical deletion of every expired row is not claimed.
- Encrypted frames waiting for an offline endpoint are removed after recipient
  acknowledgement or endpoint revocation. No independent time-based frame
  expiration was verified.
- Push registrations persist while authorized or leased.
- Alert payloads are encrypted at rest and delivery records are pruned by the
  relay lifecycle.
- Revocation tombstones and idempotency metadata are retained only for
  consistency and replay protection.
- Aggregate counters do not contain prompts or replies.

Account deletion is available in the app and requires a fresh passkey assertion.
The Link service revokes every device push registration and Live Activity,
deletes the passkey account and device directory rows, closes active sockets,
and purges the per-account Durable Object. The service performs a second object
purge after deleting the account directory to close races with an already
authenticated request. The app removes its local account-scoped state only
after the service confirms deletion.

Logical deletion is not a guarantee that every infrastructure backup or
provider recovery copy is immediately physically unrecoverable. Cloudflare,
Apple, Hermes-host, model/tool provider, and backup retention remain subject to
their deployed policies and legal obligations.

The exact operational durations are intentionally not published here. They
should remain short, reviewed, and enforced automatically.

## 7. Apple services and permissions

| Permission/service | Why it is used | Privacy behavior |
|---|---|---|
| Camera | Pairing QR codes and optional Reflective Vision | Frames are not recorded or stored by the feature |
| Microphone | Voice conversation input | Raw audio remains on device |
| Speech recognition | Convert speech to text | On-device recognition is required |
| Photos | Select profile and agent avatars | Images are processed and stored locally |
| Approximate location / WeatherKit | Live local weather on Home | Requested only in the foreground after consent; sent to Apple Weather and not persisted by Loopdy |
| Face ID / device authentication | Passkey user verification | Biometric data is handled by the OS |
| Notifications | Agent alerts | Alert text is encrypted for the recipient device |
| Live Activities | Agent progress on Lock Screen/Dynamic Island | Shows bounded status plus session and agent labels |
| Local network | Only when a user explicitly configures direct Hermes compatibility | Loopdy Link is the production default and uses a secure outbound connection |

Apple and network providers necessarily process delivery metadata such as IP
addresses, device tokens, app topics, timing, and service diagnostics according
to their own policies.

### Loopdy Card requests

Build 3 makes no third-party Card data requests. Cards contain embedded values,
and both the Hermes plugin and iOS app reject nonempty `data_sources`. Opening a
Card therefore does not disclose the device IP, timing, URL, or query to a Card
source host. See [Loopdy Cards](LOOPDY_CARDS.md) for the static release contract.

## 8. Privacy manifest

The app declares:

- Tracking: **false**
- Tracking domains: none
- Collected data: a linked device identifier used for app functionality
- Required-reason API use: preferences and elapsed-time measurement

Approximate location is sent only to Apple Weather to service the foreground
weather request and is not persisted by Loopdy. Apple excludes request-only,
non-retained data and data collected by Apple services from the developer's
App Privacy collection disclosure.

Loopdy does not declare user content as collected by its cloud because the
current deployed frame-routing path receives authenticated ciphertext, has no
frame-decryption operation, and does not retain a readable session store. This
classification depends on the documented key-establishment design. Review it
with qualified privacy counsel before release.

This conclusion must be revisited if any of the following changes:

- Cloud code gains a content-decryption key
- Pairing or sender-key provisioning changes the documented trust assumptions
- Message, transcript, attachment, or prompt content is logged
- Readable content is added to D1, Durable Object, KV, R2, Analytics, or queues
- Retention expands beyond real-time delivery needs
- A third-party telemetry or customer-support SDK is added
- Live Activity state begins carrying unrestricted user content

## 9. Live Activity and Lock Screen privacy

The app supplies Live Activities with a sanitized projection. It maps tool names
to generic categories, limits text, and excludes prompts, arguments, attachments,
and complete model output.

The session title, agent name, and progress state can still be visible on the
Lock Screen. Users who require shoulder-surfing protection should disable Live
Activities or notification previews in iOS settings.

## 10. Logging and telemetry

The iOS app includes no analytics, advertising, crash-reporting, or behavioral
tracking SDK. Production code must not log:

- Credentials or private keys
- Passkey assertions
- APNs tokens
- Account or device authorization material
- Plaintext prompts, responses, attachments, or decrypted notifications
- Full server error bodies

Cloudflare platform logs and Apple service logs may contain provider-level
network and delivery metadata. Operators should keep application logging
redacted and minimize retention.

## 11. Security limitations

- This project makes no claim of an independent third-party security audit.
- The custom protocol depends on correct implementation at both iOS and Hermes
  endpoints.
- A compromised authorized endpoint can read account content.
- A compromised device after unlock can read local caches.
- Manual pairing relies on the user comparing the host's separate 16-character
  verification code; QR pairing carries the full key commitment.
- The account service provisions notification sender trust. No separate
  transparency or continuity system verifies it.
- E2E content encryption does not provide anonymity or hide traffic patterns.
- Availability depends on Cloudflare, APNs, the Hermes host, configured
  providers, and Apple services used by enabled features.
- Live Activity state is privacy-reduced, not equivalent to the encrypted alert
  channel.
- Direct Hermes client code exists but is not active in the production
  composition. Do not assume the production Loopdy Link path tests it.

## 12. Export and legal review

The app implements cryptographic operations using Apple's CryptoKit and
Security frameworks and declares that it does not use non-exempt encryption.
That setting may be appropriate for system-provided, standard cryptography, but
export classification depends on distribution, functionality, and current law.
Confirm it through Apple's current export-compliance process and, when needed,
with qualified counsel. This documentation is not an export determination.

Report suspected vulnerabilities privately using the process in
[`SECURITY.md`](../SECURITY.md).
