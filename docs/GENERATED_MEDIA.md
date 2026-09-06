# Generated media

Plugin 2.8.0 supports Loopdy app 1.8.0's generated image and video activity cards
without adding a media service or changing Hermes core.

## Resolve one exact call

The encrypted `generated_media.resolve` workspace operation accepts exactly:

- `agentId`: the selected Hermes profile.
- `storedId`: the canonical stored session.
- `turnId`: the live activity turn coordinate or hydrated `history-turn-…` coordinate.
- `toolCallId`: the exact persisted generation tool call.

The host reads profile-scoped Hermes history and requires one matching call and
one matching result. It recognizes `image_generate`, `video_generate`,
`xai_video_edit`, and `xai_video_extend`, including an exact named call through
the public `tool_call` discovery bridge. Similar tool names and arbitrary shell
commands are not generation calls.

Successful public tool lifecycle events retain only the profile/session/turn/
call identity in `plugin-data/loopdy/generated-media.sqlite3`, bounded to 512
recent records. That ledger reconciles live Link turn IDs with stored history;
it is not an alternative source of result content. A hydrated history turn can
resolve independently of a live ledger entry. Ambiguous or not-yet-persisted
calls produce the bounded `generated_media_not_ready` workspace error.

A successful response repeats `storedId`, `turnId`, and `toolCallId`, and returns
`state`, `omittedCount`, and `attachments`. States are `ready`, `oversized`, or
`unavailable`. Accepted artifacts have opaque `id`, safe `fileName`, `mimeType`,
and `byteCount` fields; local source paths are not returned. Oversized media is
reported explicitly even when the attachment cache refuses its bytes.

Resolution passes the stored tool result through Hermes' media-delivery policy
and the existing profile-scoped attachment cache. Cache identity is stable for
the stored session and exact tool call, so a cached live result can be restored
from history after its original source file disappears. Missing or evicted bytes
remain unavailable rather than triggering an arbitrary network fetch.

## Transfer bounds

| Direction | Per artifact | Aggregate | Chunk |
| --- | --- | --- | --- |
| Host agent to device | 25 MiB | Generated result: eight artifacts, 32 MiB | 64 KiB, at most 400 chunks per artifact |
| Device upload to host | 8 MiB | 24 MiB per message | 64 KiB, at most 128 chunks per artifact |

`attachments.resolve` exposes agent attachment metadata within the host limit.
`attachments.fetch` accepts `agentId`, `attachmentId`, and `offset`; it returns
base64 `data`, the same `offset`, and an advancing `nextOffset`, or `null` at EOF.
Offsets at or beyond EOF, absent artifacts and wrong-profile lookups fail closed.
The client must validate each chunk and the declared final byte count, own
cancellation, and reject nonadvancing or truncated transfers.

The existing host cache remains bounded to 500 items and 250 MiB per profile.
Generated-media limits do not expand phone uploads, generic workspace payload
limits, or filesystem grants. Workspace Files remains a separate host-granted,
read-only API; no mobile Files permission is implied by a generation result.

## Compatibility and activation

Card-template list/install/remove operations are statically declared in the
workspace parser and dispatcher. They no longer depend on registration-time
mutation of plugin classes. Existing card capability negotiation, public
Marketplace trust, bounded Inbox card projection, and legacy ready envelopes
remain unchanged.

Source publication, host installation, and active gateway loading are separate.
A compatible app must handle an older host's unsupported-operation response;
a version stamp alone does not prove that a running host loaded this source.
