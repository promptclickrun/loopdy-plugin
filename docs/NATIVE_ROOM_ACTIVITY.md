# Native hosted-room tool observations

This optional adapter consumes the public current-main Hermes
`on_room_member_activity` observer. It uses no private session/task dictionaries,
hidden-session subscriptions, new WebSocket, scheduler or model execution loop.
It is unavailable on released Hermes versions without the hook.

The enabled plugin registers only when the hook appears in public `VALID_HOOKS`;
`register_hook` accepting a name alone does not prove support. Unload retires the
callback lease, clears all feeds and fences already queued old callbacks. Native
context advertises `native-room-activity-v1` only with a live supported
registration. `registered_unobserved` remains honest until a valid tool callback
arrives; the plugin never changes the host's tool-progress configuration.

## Transport and exact DTOs

All operations are POST under `/api/plugins/loopdy/native/groups/activity/`,
using the existing real native Session, context `If-Match`, and canonical
`X-Loopdy-Request-ID` headers. Responses follow the native success/error header
rules in [Native workspace API](NATIVE_WORKSPACE_API.md).

| Suffix | Exact request | Successful result |
| --- | --- | --- |
| `open` | `{roomId}` | Empty `FeedPage`, cursor/highWater 0 |
| `poll` | `{roomId,streamId,after,limit}` | `FeedPage` |
| `close` | `{roomId,streamId}` | `{schemaVersion:1,roomId,streamId,closed:true}` |

```text
FeedPage = {
  schemaVersion:1, runtimeId, roomId, streamId,
  sourceState:"registered_unobserved"|"observed"|"unsupported_payload",
  upstreamLoss:"unobservable",
  openedAt:UnixMilliseconds, expiresAt:UnixMilliseconds,
  cursor:integer, highWater:integer, hasMore:boolean,
  resetRequired:boolean, resetReason:null|"buffer_loss"|"projection_loss",
  droppedTotal:integer, projectionDrops:integer,
  events:[{
    observationSequence:integer, observedAt:UnixMilliseconds,
    roomId, memberId, threadId, turnId, taskId, executionGeneration:integer,
    sourceSequence:integer|null,
    kind:"tool.started"|"tool.completed",
    tool:{id,name,durationMs:integer|null},
    arguments:{state,text}, result:{state,text}
  }]
}
```

Every shown property is required. Detail `state` is exactly `available`,
`unavailable`, `omitted_size` or `omitted_sensitive`; `text` is a string only
when available, otherwise null. No inferred profile, success, current-running
or durable log-event ID is included.

Each stream is a server-minted, disposable view coordinate, bound to the actual
verified principal/context and room. It is not a credential. Before opening and
polling, the existing fixed native `groups.state` path validates current room
identity, authority epoch and immutable roster. Changes retire the feed. Native
workspace authority applies; this does not add a fictional per-person room ACL.

## Semantics, omissions and loss

Display started as **Started**, not proof the tool is still running. Display
completed as **Finished; outcome not reported**, not succeeded. Match rows by
runtime/feed, room/member/task/execution generation and native tool ID. Source
turn/thread coordinates remain exact. Canonical native room logs, final
messages, approvals and retry/cancellation remain authoritative.

The feed begins with callback receipt after opening, not source execution after
opening: an upstream event can already be queued. `observedAt` is plugin receipt
time. Nothing is retained before a viewer explicitly opens a feed; no source
text is written to disk.

Only `payload.args` and `payload.result` are optional detail sources. Missing,
non-JSON, invalid-control or oversized data is explicitly unavailable/omitted;
escaping can require omission to satisfy the encoded observation ceiling.
Existing known-credential patterns and credential-bearing object keys suppress
details. This is conservative screening, not universal secret detection.
Details never replace or enter durable history. Messages, reasoning, approval
payloads, duplicate preview text and tool-success inference are excluded.

Hermes' upstream observer queue silently drops oldest entries and has no public
drop counter. `upstreamLoss` therefore ALWAYS says `unobservable`; gaps in its
session-wide sequence cannot measure loss. The local observation sequence and
drop counters describe only this plugin feed. Equal bounded source observations
with a source sequence are deduplicated while retained, not durably.

If the requested cursor predates discarded entries, or a room-bound callback
cannot safely project its required coordinates, return resetRequired with empty
events and cursor=highWater. Clear transient rows, reconcile native room
state/log and open a fresh feed. Do not invent the missing activity. A source
sequence is not a room-log cursor.

## Bounds, failures and lifecycle

- 16 feeds/process, 128 observations and 256 KiB encoded events/feed (4 MiB
  total), plus bounded digest/coordinate bookkeeping.
- 60-second inactivity lease; authenticated successful polls renew it.
- Poll limit 1..8, cursor 0..highWater; responses <=196608 UTF-8 bytes.
- Each detail <=8192 UTF-8 bytes and each observation <=20480 encoded bytes.
- Room/member/thread/turn/task IDs <=128 ASCII identifier characters; native
  tool ID <=512, name <=128; safe integers, finite duration <=24 hours.

Shared native errors remain 401/412/428/422. `activity_unavailable`503 means no
supported live observer, `activity_capacity`429 a full feed budget,
`activity_not_found`404 mismatched principal/room, `activity_reset_required`410
an expired/retired stream or changed room authority/roster. `room_unavailable`
is404 for an unavailable returned room or503 for an unverified native read;
malformed room data is `room_state_invalid`503. Errors never create a replacement
stream or reflect raw source content.

Request cancellation does not create a replay obligation: an abandoned open is
bounded by its idle lease, polls are reads, and a closed stream is not silently
reopened. Owner/context checks bracket awaits. As with ordinary native HTTP,
revocation cannot recall data already delivered.

Tests use actual stock serve auth and the public hosted-service lifecycle/emitter
in a synthetic home. No real provider call, message send, installed runtime
change, deployment or activation is performed.
