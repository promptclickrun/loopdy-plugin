# Native Project Git: read-only review

The optional `native-project-git-read-v1` capability adds three fixed POST routes
under stock `/api/plugins/loopdy/native/projects/git`. It reuses the existing
`WorkspaceGitService`, not the weaker stock native Git projection. No new
filesystem-grant database, Link identity, arbitrary command proxy, remote
operation or mutation route is introduced.

Native Hermes login is sufficient. Project/session selection is an explicit
normal application action, not a new pairing or grant ceremony. It does not
create or adopt a Workspace Files grant.

## Exact native contract

Use the same actual verified Hermes Session, context `If-Match` and canonical
`X-Loopdy-Request-ID` as other new native routes. Success echoes both headers;
plugin errors echo a valid request ID but do not issue a new ETag. Native
middleware may reject earlier without those headers.

| POST suffix | Exact body |
| --- | --- |
| `capabilities` | `{agentId,sessionId,workspaceId}` |
| `status` | `{agentId,sessionId,workspaceId}` |
| `diff` | `{agentId,sessionId,workspaceId,path,side,statusToken,offset,limit}` |

`agentId` is the canonical profile ID (64 characters maximum). `sessionId` is
the **full native stored session ID**, not a Link chat coordinate, runtime ID,
prefix, title or guessed continuation (128 ASCII identifier characters).
`workspaceId` is the exact native registered Project ID (80 ASCII identifier
characters), not a Files grant ID or project slug. The latter two accept
`[A-Za-z0-9][A-Za-z0-9._:-]*`, including full UUIDs. Diff `path` is relative to
the verified root, <=4096 UTF-8 bytes, with no traversal or control/credential
paths. `side` is `staged` or `worktree`; `offset` is 0..100000 and `limit` is
1..500 strict integers.

Successful responses use the existing Project Git camelCase schema:

```text
Capabilities = {
  schemaVersion:1,
  capabilities:{status:true,stage:false,commit:false,push:false,fetch:false,
                pull:false,arbitraryCommand:false},
  workspaces:[{workspaceId,label,visibility:"private",operations:["status"],
               remotes:[],branches:[],mutationsEnabled:false}]
}
Status = {
  workspaceId,statusToken,
  head:{oid:string|null,branch:string|null,detached:boolean,
        upstream:string|null,ahead:integer,behind:integer},
  files:[{path,originalPath:string|null,index,worktree,kind,
          insertions,deletions,isBinary:boolean}],
  filesPage:{offset:0,limit,returned,total,nextOffset:null,complete:true},
  staged:{files,insertions,deletions},changes:{files,insertions,deletions},
  conflicts:[path],
  conflictsPage:{offset:0,limit,returned,total,nextOffset:null,complete:true},
  dirty:boolean
}
Diff = {
  path,side,availability:"available"|"binary"|"oversized",offset,
  lines:[{kind,oldLine:integer|null,newLine:integer|null,content}],
  nextOffset:integer|null,previewContent?:string
}
```

File kinds: ordinary, renamed, unmerged, untracked. Diff row kinds: header,
hunk, context, addition, deletion, no_newline. Status insertion/deletion/binary
facts aggregate the two sides; they are not invented per-side counts.
`previewContent`, when supplied on page zero for Markdown/text, contains the
complete selected side up to 65536 bytes. Staged uses the index; worktree never
falls back to staged content.

## Public metadata and root boundary

The server validates/normalizes profile, requires an existing profile directory
and existing `state.db`, and opens public `SessionDB(..., read_only=True)`.
It calls exact `get_session(full_id)` and closes the handle. It does not use a
prefix resolver, resume/create a session, bootstrap/heal a missing session DB or
read private runtime globals. Stored profile metadata must agree when present;
legacy null ownership remains scoped by the exact canonical profile DB path.

Project lookup is only the fixed public `projects.get {profile,id}` dispatcher.
Returned ID must equal the request; a slug resolving to a different ID is not
accepted. Archived, absent or malformed Projects fail explicitly. This public
Hermes metadata getter can initialize/migrate its own native Projects metadata;
the guarantee is **read-only Git/source files**, not zero host-metadata writes.
The plugin neither creates a shadow registry nor opens a private Projects DB.

The first supported root is the Project's explicit primary path, also present
as exactly one primary registered folder. There is no process-CWD or first-folder
fallback. The exact stored session CWD must be the same real directory as that
primary root. Nested/secondary folders are not implicitly broadened into root
access. Shared filesystem policy rejects symlink roots, credential/control
directories, the host home, and roots enclosing Hermes control state. The Git
engine independently verifies that it is the Git worktree root.

Before and after I/O, the server compares Project ID/primary folder metadata,
stored session association and root device/inode. Missing or changed
associations reject the response. This is observational validation, not an
atomic metadata/filesystem lease; external changes followed by restoration
(ABA) cannot be categorically excluded.

## Hidden canonical Bot Chat is supported

Hidden does not automatically mean internal. A hidden ordinary target is
permitted only when public read-only `get_session_by_title("Bot Chat")` and
`get_compression_tip(canonical.id)` prove that its exact ID is the canonical
root or current compression tip. Both rows must exist, remain unarchived and
have eligible metadata. Intermediate/other hidden sessions are not inferred
from title fragments, pointers or timestamps.

Room plumbing, bot_room, delegated/tool, subagent, worker, Kanban-worker and cron
sessions are not admitted by this review endpoint, even if a canonical title
matches. The plugin does not unhide/unarchive them or borrow their execution
authority. Visible ordinary sessions retain the same exact Project/CWD check.

## Tokens, paging and explicit unsupported states

The engine's original `sha256:<64hex>` statusToken hashes repository identity,
HEAD, index bytes, changed worktree file contents/modes/sizes and full porcelain.
The adapter does not fabricate a token from a filename/count or claim a durable
immutable snapshot. Tokens are optimistic content-change preconditions checked
before/after diff; Project/session association is separately rechecked.

Status must fit the existing complete 500-file/conflict and 160000-byte bounds.
The engine has no follow-on status paging API: incomplete results are rejected
with 413, never returned as complete or exposed as invented next-page routes.
Diff paging is real, with the same expected token on each request.

Unmerged/combined `@@@` diffs explicitly fail instead of becoming empty
available results. Binary/oversized supported-side results retain the explicit
availability state, empty rows and null cursor. The engine bounds source/capture
to 2000000 bytes, 100000 rows, 16000 bytes per row and 160000 bytes per page.

Protected status paths or rename origins block the review with an explicit
error rather than silently changing the existing codec/count meaning. All
returned diff hunks and complete previews are scanned for known credential
patterns before paging. This is conservative pattern matching, not universal
secret detection. Symlinks, unsafe hard links and unsupported file types are
rejected. Unknown errors never become an empty successful diff.

The native engine policy is always `operations:["status"]`, no remotes/branches,
mutations disabled, even if legacy host policy enables writes. Its new
read-only construction skips the unused mutation ledger entirely. Existing
Link and Files constructors/policies keep their prior behavior.

## Failures and validation

Errors use `{error:{code,message,retryable,details:{}}}` without raw paths,
commands, metadata rows or exceptions. Native auth/context statuses remain
401/412/428. Wrong profile/Project/session is404; changed association is409
`scope_changed`; changed token409 `status_changed`; complete status overflow413
`status_oversized`; combined/unsupported diff422 `diff_unsupported`; protected or
credential content422 `sensitive_data_blocked`; non-repository422
`project_not_repository`; unavailable engine503; timeout504 `git_timeout`.
Malformed fields are422. None authorizes a mutation or transport fallback.

Qualification uses synthetic repositories, public session/Project fixture APIs
and stock serve authentication in credential-free temporary homes. It verifies
canonical hidden chat, exact scopes, separate diff sides, token changes,
unsupported conflicts, incomplete status, sensitive paths/content and no
index/source mutation. No production repository, deployment, provider or
installed runtime is touched.
