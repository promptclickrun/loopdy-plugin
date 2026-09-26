# Apps tab: Artifacts and Media

The bighelp app's Apps tab shows what an agent made. Both routes follow the
native context/ETag/request-ID contract and never return host paths the phone
could not already see.

## Artifacts (`native-workspace-recent-v1`)

`POST workspace-files/recent` with `{"path": null}` returns the same listing
shape as `workspace-files/list` for the configured `terminal.cwd`, newest first
(at most 300 rows):

- Files the serving profile's agent created or edited (`write_file`, `patch`)
  or delivered (`MEDIA:`), ranked by when it wrote them. Paths come from the
  profile's own `state.db`, must still exist, and are re-opened `O_NOFOLLOW`
  below the root, so history can never point outside the workspace.
- Plus files in the top two folder levels, ranked by creation time. Hidden
  entries, dependency/build folders, bundles, housekeeping files (logs, locks)
  and code repositories (folders with `.git`) are skipped.

A workspace can hold millions of files, so this never walks the whole tree. It
answers in about a second on a large Mac workspace.

## Media (`native-agent-media-v1`)

`POST attachments/recent` with `{"agentId", "limit"}` (1-36) returns
`items`: `id`, `fileName`, `mimeType`, `byteCount`, `storedId`, `createdAt`.
They are the newest pictures and videos the agent delivered with `MEDIA:` or
made with `image_generate`/`video_generate`. Each goes through the gateway's
delivery policy and the same attachment store as chat attachments; bytes are
fetched with `attachments/fetch`.
