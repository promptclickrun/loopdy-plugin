# Optional native-host notifications

Managed notification enrollment is separate from native Hermes authentication and
from Loopdy Link chat pairing. Foreground native chat does not require this plugin,
an APNs enrollment, or access to Loopdy's chat relay.

This source adds account-scoped sending authority, not an operator-wide relay key.
The host receives only a public grant for one account device, recipient encryption
key, profile, allowed event types and expiry. APNs keys and tenant-wide credentials
never go to the host. The existing independently configured relay APIs remain
available for legacy installations.

## Activation and capability discovery

Hermes mounts `dashboard/plugin_api.py` through the supported plugin dashboard
loader at `/api/plugins/loopdy`. Its stock authentication protects the new routes.
Installation, enablement, mounted API and registered lifecycle observers are
separate states. Installing files does not hot-mount this router or activate hooks.
Use the host owner's supported activation/restart process separately when needed.

`GET /notifications/capabilities` returns version 1, `hostKeyId`, `hostPublicKey`,
`managedEnrollmentSupported`, `supportedEventTypes`, `richLiveActivitySupported`,
and a `producerCapabilities` object. Supported events allow enrollment before the
first turn; producer booleans separately report lazy in-process observer loading.
Supported event types are `session.completed`, `session.failed`, and
`approval.required`. `producerCapabilities.nativeApproval` is true only after both
named approval observers are supported by the installed SDK and registered in this
process. Older hosts can retain their two-event enrollment; no existing grant is
expanded when support grows.
The public key is
uncompressed P-256 X9.63, unpadded base64url. Its ID is base64url SHA256 of those
65 bytes. The independently generated private key lives under the current Hermes
home's `plugin-data/loopdy/managed-notifications/`, outside the replaceable plugin
installation. The directory and key must be owner-only; symlinks are rejected.
There is no claimed loaded revision inferred from files on disk.

Producer booleans reflect callbacks registered in the responding process. A mounted
API alone may truthfully report false. A capability is not a delivered push receipt.
The managed private-store worker currently requires POSIX file locking. Unsupported
platforms fail this optional feature without removing the legacy API.

## Enrollment

1. The app signs in to its Loopdy account, registers its mobile device and completes
   existing account APNs recipient enrollment. No Hermes chat host pairing is needed.
2. The app reads the authenticated host capability/public key.
3. The app uses its **signed mobile identity**, not a host bearer, to create a grant
   at `https://link.loopdy.app/v1/notifications/host-grants`. It chooses a profile,
   event types and an expiry bounded by the current APNs recipient lease. Use the
   intersection of the app-supported set, this host's `supportedEventTypes`, and
   the user's requested events. Request `approval.required` explicitly for new
   approval-enabled grants, never by rewriting a saved completion-only grant.
   Freeze the selected set and request bytes with the idempotency key across retries.
4. The app saves grant-scoped sender trust before enabling delivery. It then calls
   host `POST /notifications/enroll` with
   `{version:1,idempotencyKey:<lowercase UUID>,grantId:<lowercase UUID>}`.
5. The host proves possession of its own key to the fixed first-party account
   endpoint, checks the confirmed public grant, and persists the receipt.
6. The app subscribes an exact native session with
   `PUT /notifications/enrollments/<grantId>/sessions` and
   `{version:1,profile,sessionId,enabled:true}`. The host uses the supported read-only
   profile SessionDB, exact stored ID and `profile_name`. Missing/unknown ownership
   is denied rather than guessed. There is no all-sessions target.

Readback: `GET /notifications/enrollments/<grantId>` checks the current cloud grant.
Local DELETE at the same path cancels local work but **does not revoke cloud
permission**. The app separately deletes the signed-mobile cloud grant with
`{version:1,expectedRevision}`. Device/account removal also revokes managed grants.
There is only one non-revoked host/profile/recipient grant at a time; list and reuse
its receipt, or revoke it explicitly before replacing it. Token/key/revision changes
invalidate the old grant rather than silently changing its destination.

## Significant events and retry ownership

Completion scope remains `session.completed` and `session.failed`, emitted from
real stock `on_session_end` facts only for explicitly subscribed sessions. Cancellation
is not failure; child completion/failure is not another parent alert. Existing Home
completion history and unenrolled legacy behavior remain intact.

A stable event ID is `<grantId>:<64 lowercase SHA256 hex characters>`. The digest
covers canonical JSON `[profile,sessionId,turnId,eventType]` for completion/failure.
Approval attention instead covers
`[profile,sessionId,turnId,toolCallId,"approval.required"]`. The grant prefix binds
the exact recipient/host enrollment. The encrypted LP1
payload uses the existing relay cryptography and a deterministic delivery ID:
`ng-` plus UUIDv5(URL namespace, event ID). Random encryption inputs and the exact
serialized request are persisted once. Retries reuse those bytes, not fresh
ciphertext. Host proof uses a fresh nonce on each HTTP attempt.

Alert copy is fixed (`Your agent finished` / `Your agent could not finish` /
`Your agent requested approval`), not
prompts, tool arguments, questions or error details. Existing explicit device
preferences are consulted when that recipient also exists in the legacy store.
Quiet-hours suppression is recorded durably. For subscribed recipients the managed
lane owns authorized completion/failure alerts, so the legacy sender suppresses
those same events for that recipient. It does not take ownership of legacy approvals.
The app must likewise treat foreground session updates as data, not a second banner.

After successful LP1 authentication/decryption the app resolves the exact grant
prefix, validates that grant's recipient, expiry and allowed event type, and fetches
`GET /notifications/enrollments/<grantId>/events/<eventId>` on its originating host.
That endpoint rechecks enrollment and exact current session ownership. It returns
only event ID/type, profile, session ID, turn ID and occurrence time. A tap never
executes an approval or command. Outer APNs routing fields are not authority.

## Bounded native approval attention

This additive observer uses supported `ctx.register_hook("pre_approval_request", callback)`
and `ctx.register_hook("post_approval_response", callback)`. The SDK callback payload
provides `surface`, `turn_id`, `tool_call_id`, and (when its observability context is
bound) `session_id`. Only exact `surface="gateway"`, non-coalesced native session
observations qualify. Smart assessments, CLI, unknown/custom transport surfaces,
child-session hooks, missing coordinates and contradictory profile metadata do not
queue attention. The stored session must match the exact subscribed ID and profile
through the supported read-only SessionDB. `session_key` and runtime UI IDs are never
used as substitutes; no recipient comes from command text or a home target.

A grant must explicitly include `approval.required`. The pre-hook records one
**tool-scoped attention fact**, not one notification per native pending request.
It runs just before native presentation, not after a presentation receipt. The
native hook does not supply its request ID, so no request ID is fabricated and no
command, description, decision reason or pattern key is retained. Multiple prompts
inside one tool call coalesce under one event ID. The unchanged event-detail object
retains the actual canonical `turnId`, with no composite identity relabeled as a turn.

A private `approval_attention` journal row and its frozen event request are written
atomically. A 3-second coalescing grace delays admission; expiry is at most 60 seconds
from observation (also bounded by grant expiry). These are notification limits, not
a claim about the native prompt's configured timeout. The existing worker has a
5-second idle wake interval; scheduling/network delays can cause
conservative drops. Preference suppression is a durable tombstone, not delayed replay.

All gateway post-hook dispositions (including immediate response, `notify_failed`,
interruption and timeout), exact tool completion, and exact turn end retire **unsent**
attention. Cancellation follows the same retirement while retaining the existing
Stopped/child-cohort behavior. Response-before-pre and turn-end tombstones prevent
late observations from resurrecting attention. Local removal/unsubscription also
retires it. Tombstones are bounded to 4096 per grant and retained until grant cleanup;
capacity exhaustion refuses new attention rather than dropping deduplication evidence.
No work cohort is created or marked waiting from an approval hook in this version.

The drain conservatively retires attention belonging to any previous producer
lifetime; it never restores a claim of still-pending approval from SQLite. Opening
the store from an API-only process does not itself retire a live producer's rows.
Only the process-owned worker drains. Shared-store multi-process observations that
do not belong to that worker are deliberately dropped, not replayed as live prompts.
Completion/failure retry and activity recovery behavior are unchanged.

After claiming an intent and signing, the worker rechecks exact session ownership,
subscription, event authority, local retirement, producer lifetime and expiry
immediately before transport. Retries preserve the original ciphertext, event ID,
delivery ID and expiry. Post-hook retirement racing a failed send cannot requeue it.
A response after the final local fence can still race relay admission; there is no
notification-recall endpoint. **Accepted APNs pushes cannot be recalled.** The copy
therefore says only `Your agent requested approval`, never that approval is still
pending. On tap, authenticate/decrypt, revalidate the originating grant and fixed
host event detail, then reconcile the real native pending prompt. Approval responses
remain on native `approval.respond` with the actual native request ID. APNs provides
no authority for approval buttons, commands, or automatic responses. Existing voice
observers and the explicitly selected legacy approval transport are unchanged.

## Rich Live Activities

The native app registers the ActivityKit token directly with the signed-mobile
account route `/v1/notifications/host-grants/<grantId>/live-activities/<activityId>`.
The host never receives that token. It subscribes only after cloud readback with:

`PUT /notifications/enrollments/<grantId>/live-activities/<activityId>`

Body: `{version:1,profile,sessionId,sessionReference,leaseExpires,turnId?:string}`.
`sessionReference` is unpadded base64url SHA256 of `profile + NUL + sessionId`.
Supply the canonical turn ID from the authenticated subscribed-session work
readback, especially for queued/overlapping work. Native timeline IDs are not
canonical host turn IDs.
Without it, subscription binds the currently observed generating parent, or the
next genuine parent start. A late terminal or child stop cannot bind a new activity.
Once bound, an activity cannot switch turns. DELETE removes the local subscription;
the app owns cloud revocation when retiring a token.

ContentState retains the exact rich-v1 keys: `phase`, `currentAction`, `progress`,
`completedSteps`, `activeSubagentCount`, `latestTool`, `timestamp`. It uses fixed
copy, null latestTool, zero unknown completedSteps, and legacy progress 0 while
active / 100 at terminal. Clients should not display this as a percentage.
The cloud envelope adds only existing update identity/reference/expiry fields.
There is no mandatory v2 or coarse `running` phase sent to the rich decoder.

Child membership is deduplicated and tied to its original parent turn. A failed
child does not fail the parent. Parent completion retains outstanding children;
terminal is emitted only for the bound work cohort. Current rosters are in-process
facts, not restored from old durable starts. Restart can therefore produce a stale
activity, never fabricated running progress.

Ordinary updates are latest-state coalesced to the existing 30-second relay budget.
Terminal updates bypass that delay and are durably retained until accepted or their
120-second rich-v1 expiry. Completion/failure alerts expire within 900 seconds;
approval attention expires within 60 seconds. An accepted/duplicate
receipt means relay admission, not visible delivery; expiry is not success. The
relay's queue rechecks grant and recipient validity on each attempt and just before
APNs. A token has one managed owner, with legacy registration/update fences.

## Deliberately unadvertised producer boundaries

Native clarification is supported by Hermes, but its background producer is not
integrated here (`nativeClarification=false`). Bounded approval attention is
separate from native pending-request transport and is advertised only when its
observers load. No request ID or question is fabricated. Existing legacy
approval/clarification behavior remains.
Scheduled-job/task subscriptions are not added to managed grants in this first
native-session scope; their existing legacy delivery is unchanged.

Rich v1 retains its existing terminal transport phase for cancellation, with exact
fixed `Stopped` copy and no completion/failure alert. The canonical work readback
keeps `outcome:cancelled`; outstanding children delay the terminal until settled.
The native presentation distinguishes Stopped from Finished. There is no
push-to-start implementation, synthetic liveness heartbeat, or claim of physical
APNs verification.

## Wire proof

Headers: `x-loopdy-host-key-id`, `x-loopdy-timestamp`, `x-loopdy-nonce`,
`x-loopdy-signature`. P-256 ECDSA/SHA256 signature uses P1363 (64 bytes), unpadded
base64url. The signed UTF-8 transcript joins these fields with newline and no final
newline:

1. `loopdy-notification-host-v1`
2. uppercase HTTP method
3. exact query-free path
4. grant UUID
5. decimal Unix timestamp
6. random 32-byte base64url nonce
7. lowercase SHA256 hex of the exact HTTP body bytes

The clock window is 120 seconds, with durable nonce replay protection for the whole
accepted timestamp window. No account bearer, arbitrary relay URL, shared HMAC, or
APNs secret is accepted by the host enrollment API. All redirect responses are
rejected. New clients must negotiate these routes through capabilities rather than
assuming that equal package version strings imply loaded support.
