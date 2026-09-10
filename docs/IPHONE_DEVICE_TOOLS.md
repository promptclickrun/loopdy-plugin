# iPhone tools for Hermes

Status: released to internal TestFlight in Loopdy 2.0.1 (13), with plugin 2.11.0.
Apple processing and membership in all four internal groups were verified on
September 10, 2026 for build 504a2307-1bbb-4443-bd40-ee24b05bf660. Build 11 does
not contain this feature; upload 12 failed processing. Physical-device
Health/EventKit acceptance remains pending and is separate from source and
simulator results.

## User contract

Permissions contains independent Apple Health, Calendar and Reminders controls.
Every control starts off. Enabling one requests its native iOS permission from
that explicit foreground action. Calendar and Reminders authorize direct reads,
creation, updates and deletion after enablement, with no per-operation approval.
Health is read-only. OS permission by itself never enables agent access.

Grants are scoped to the current phone, phone authorization epoch and selected
host. Turning a control off invalidates active work immediately. Switching host,
signing out, backgrounding or losing protected-data access invalidates in-flight
operations. Account erasure deletes persisted grants and mutation outcomes.
Re-enabling a grant cannot revive a read started under an older grant revision.

The phone must be open, unlocked and connected. No background execution or wake-up
guarantee is offered. Unavailable or denied access is a failure, never fabricated
empty data. Apple deliberately does not disclose Health read authorization;
an empty Health result may mean no records or denied access. The UI must preserve
this distinction.

Requested data is sent to the selected Hermes host and its AI provider. It may
be retained in the ordinary conversation/tool history. It is not used for
advertising or analytics. Loopdy's mutation journal stores only request hashes,
expiry and identity/reconciliation metadata, never Health samples, event text,
reminder text or request arguments. The journal is protected, atomically written,
excluded from backups and bounded to 512 records / 2 MB. No raw Apple data should
be added to diagnostics.

Hermes and the future Loopdy Native harness remain complementary. The unfinished
Native harness is not required and is not treated as operational.

## Components and required versions

| Component | Responsibility |
| --- | --- |
| Hermes `ToolExecutionContext` extension | Carries immutable authenticated ingress ownership to official plugin handlers and hooks, with official session/turn/tool-call IDs. |
| Loopdy plugin 2.11.0 | Registers `iphone_health`, `iphone_calendar`, `iphone_reminders`; targets the verified originating phone and correlates results. |
| Link relay with `directed-frames-v1` | Negotiates exact-recipient delivery and queues only for that active paired device. Legacy sockets never receive a broadcast fallback. |
| iOS `DeviceToolPermissions` | Persists opt-in grants and fences asynchronous work by scope/revision. |
| iOS `DeviceToolCoordinator` | Validates envelopes, deadlines, ownership and grants; bounds concurrency and journals mutation outcomes. |
| iOS `AppleDeviceToolService` | Executes the finite HealthKit/EventKit operations with authorization checks around native boundaries. |
| iOS live socket | Receipts authenticated requests before native execution and sends directed correlated results without blocking chat streaming. |

The generic Hermes source extension is documented in
`docs/TOOL_EXECUTION_CONTEXT.md` in the Hermes checkout. It is required: plugin
registration omits phone tools on older Hermes versions. The context is
runtime-only, excluded from prompts, tool schemas, transcripts and session
persistence. Queued events retain exact ownership; different owners are not
merged or steered into each other's turns. CLI, cron, restart-recovered events
and delegated children lack phone context and fail closed. Never infer a phone
from the last active chat or model-provided arguments.

The plugin constructs context from the verified Link frame's phone ID and
phone epoch, with the authenticated host ID as an attribute and profile as
scope. Phone and host authorization epochs are independent.

## Transport and ownership

The existing encrypted Link connection carries version-1
`device.tool.status`, `device.tool.request` and `device.tool.result` payloads.
The outer frame's `targetDeviceId` must identify an active opposite-role device
in the same account. Unknown, revoked, wrong-role, self or unsupported targets
are rejected without fan-out. This controls routing; existing account content
encryption is shared across paired account participants, not a new
recipient-specific encryption scheme.

Requests and results bind `requestId`, `deviceId`, `hostId`,
`authorizationEpoch`, `sessionId`, `agentId`, `turnId`, `operation` and
`sentAt`; requests also carry `expiresAt` and bounded arguments. Official
tool-call coordinates generate a stable request ID. Reusing that ID with
different arguments produces a conflict. The native request limit is 20 KB;
the plugin additionally limits arguments to 16 KB. Native results are bounded
to 128 KB. Host timeout is normally 30 seconds (bounded to 20–60 seconds);
the native envelope permits no more than 120 seconds.

Status is advisory. Every operation still checks the live native grant,
foreground/protected-data state, selected host, account and expiry. Results
recheck those conditions after native execution and while waiting for the
outbox. Reconnect or backpressure cannot replay private results after permission
revocation, ownership change or downgrade to a legacy relay. A pending private
result without its original in-memory authorization guard is retired through
authenticated outbox reconciliation.

Native work permits at most four active operations and one mutation. The plugin
keeps bounded pending requests and metadata-only mutation outcomes; read payloads
are returned only to their active caller, not cached for later retries.

## Supported operations

| Tool | Operations and constraints |
| --- | --- |
| `iphone_health` | Read bounded raw samples by type, explicit ISO-8601 start/end and IANA time zone. Maximum 31 days and 200 total records. |
| `iphone_calendar` | List events in a bounded date range; create; update/delete an exact ID with expected revision. |
| `iphone_reminders` | List with optional list IDs, completion and undated filters; create; update/delete an exact ID with expected revision. An optional date filter requires start, end and time zone together. |

Health covers steps, walking/running distance, active/basal energy, flights,
exercise/stand time, sleep, heart rate, resting/walking heart rate, HRV, oxygen
saturation, respiratory rate, blood pressure, height, mass, BMI, lean mass, body
fat and workouts. The schema is the authoritative finite catalog.

Health results include query coverage (`start`, `end`, `timeZone`, `limit`,
`returnedCount`, `truncated`, `aggregation: raw_samples`). They are not
HealthKit statistical aggregates. Never describe a truncated raw query or empty
result as a complete daily/weekly total or zero health activity.

Calendar creation accepts title/start/end/time zone and optional calendar,
location, notes and URL. Recurring event results carry `occurrenceStart`;
updates/deletes of recurring events require that exact occurrence and use
EventKit's single-occurrence span. Whole-series writes are not exposed.
Read-only calendars and stale revisions fail explicitly.

Reminders accept title, list, start/due date, time zone, notes and priority;
updates also accept completion. Both native APIs recheck system authorization
before execution. Neither API is bridged through arbitrary selectors, an
additional HTTP service or model-supplied executable code.

## Mutation reconciliation

Persist the request fingerprint as started before calling EventKit. Completed
mutations retain only ID/revision/deleted metadata. A duplicate completed request
returns the known result. A started request without a confirmed outcome returns
`outcome_unknown` and is never automatically executed again. A callback failure
after a possible commit is also uncertain; inspect current native state before
proposing a fresh change. The host must never turn a timeout into a blind write
retry with a new identity.

Permission, stale-owner, expired, unsupported, busy, stale-revision, unavailable,
persistence and uncertain outcomes remain distinct. Error strings must be bounded
and sanitized. No operation should make the chat composer unusable or block the
socket receive loop while an Apple permission prompt/query is pending.

## Release metadata

Keep both HealthKit usage-description keys in the app Info.plist because the
shared authorization API is linked even for reads. The update description must
truthfully state that Loopdy does not change Health data. Both authorization
calls pass an empty toShare set; health.write is not an allowed operation.
Do not mistake an Info.plist description for permission to add Health writes.

## Regression and acceptance requirements

Native suites:
`DeviceToolPermissionsTests`, `AppleDeviceToolServiceTests`,
`DeviceToolCoordinatorTests`, `DeviceToolFileJournalTests`,
`LoopdyLinkDirectedDeviceToolTests`, existing socket/backpressure and account
erasure suites, and `DeviceToolPermissionsUITests`.

Plugin tests exercise registration with/without supported Hermes context,
authenticated ownership, independent phone/host epochs, same-second grant
transitions, directed frames, correlation, timeouts, concurrent identities,
mutation deduplication, uncertain writes and non-caching of private reads.
Hermes tests cover runtime-only context propagation, queued owner separation,
delegation isolation and official tool-call identifiers. Relay tests verify
single-device queues and negative routing without legacy fallback.

Run iPhone and iPad composer interaction checks alongside this integration.
Preserve the full visible input focus target and microphone/Send alignment in
`ComposerInteractionUITests` and the chat interaction contract.

Physical-device acceptance requires real, explicitly enabled OS permissions:
read a known Health sample; list and create/update/delete disposable Calendar
and Reminders records; verify exact revision conflicts; turn each permission
off during a pending read; switch host; lock/background; reconnect. Simulator
and injected-boundary tests do not establish those real-data outcomes.

Apple references:
[HealthKit privacy](https://developer.apple.com/documentation/healthkit/protecting-user-privacy),
[Health authorization](https://developer.apple.com/documentation/healthkit/authorizing-access-to-health-data),
[EventKit calendar access](https://developer.apple.com/documentation/eventkit/accessing-calendar-using-eventkit-and-eventkitui).
