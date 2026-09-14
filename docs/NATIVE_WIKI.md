# Native Wiki: Hermes login is sufficient

Native Wiki uses the authenticated Hermes Session's verified provider/user ID
and the explicitly selected existing profile. There is **no additional pairing,
key proof, device enrollment, device epoch, or host approval ceremony**. Add Wiki
is normal explicit folder selection. Same-principal sessions on different
devices share native Wiki connections and can reconcile the same upload.

This is separate from the existing paired Link authority, which keeps its own
account/device checks. No native principal is disguised as a device ID. iOS
Health/Calendar/Reminders consent and model-turn provenance are separate and are
not granted by native Wiki authentication.

## HTTP contract

Feature `native-wiki-v1` appears in authenticated `/native/context` on secure
traversal platforms with the implemented native adapter and required public
profile helpers. Availability does not promise that every folder is eligible or
that a damaged/unknown-version local journal can be opened.

All paths start `/api/plugins/loopdy/native/wiki/`, use POST JSON, and require
the existing native `If-Match` and canonical `X-Loopdy-Request-ID`. Those headers
are stale-context/request correlation, not another credential or pairing step.
Success echoes both headers; errors echo the valid request ID, not a new ETag.
The stock auth/disabled-plugin middleware can reject before plugin headers exist.

Every request includes `agentId`, matching an actual Hermes profile. Remaining
exact fields:

| Suffix | Required fields besides agentId | Optional fields |
| --- | --- | --- |
| `roots` | none | none |
| `connect`, `resolve` | `folderPath` | none |
| `list` | `wikiId,path,offset,limit,query` | `revision` |
| `read`, `image` | `wikiId,path,offset,limit` | `revision` |
| `search` | `wikiId,query,mode,offset,limit` | none |
| `save/begin` | `wikiId,path,baseRevision,operationId,totalBytes,sha256` | none |
| `save/chunk` | `operationId,offset,data` | none |
| `save/commit`, `save/status` | `operationId` | none |
| `disconnect` | `wikiId` | none |

Actor, principal, account, host, device, epoch, writable, source-kind, arbitrary
method and URL fields are not accepted. Native authority is derived only by the
server from the actual Session and serving state namespace, never these bodies.

Existing Wiki wire DTOs remain unchanged:

```text
Root = {wikiId,name,writable,sourceKind,generation,folderPath,supportsCreation}
roots -> {roots:[Root]}
connect/resolve -> Root
list -> {wikiId,path,parent,revision,offset,limit,total,
         entries:[{name,path,kind,size}],nextOffset}
read/image -> {wikiId,path,availability,size,offset,data,text,revision,nextOffset,
               maxFileBytes?}
search -> {wikiId,query,mode,matches:[{path,title,snippet,revision}],
           nextOffset,isComplete,indexedAt}
save/begin,save/chunk -> {operationId,status:"receiving",nextOffset,totalBytes}
save/status -> receiving OR terminal result
save/commit -> {operationId,status:"committed"|"conflict"|"failed"|"indeterminate",
                revision:string|null,errorCode?}
disconnect -> {wikiId,disconnected:true}
```

`parent`, `nextOffset` and incomplete/binary convenience `text` can be null.
`maxFileBytes` appears for oversized file metadata; oversized data is empty and
cannot be paged as a misleading truncated file. Images are inert byte chunks,
not executable resources. Search explicitly reports incomplete scans.

Revision remains `wiki-v1:<32hex grant generation>:<64hex hash>`; new-file
base revision is `wiki-new-v1:<32hex grant generation>`. Maximum save 1 MiB
Markdown, decoded chunk 65536 bytes, list/search 100 entries and conservative
encoded payload/result 120000 bytes. Existing strict path, type, byte and
pagination validation is shared with Link.

## Authority and folder safety

`connect` creates an explicit native-principal connection for a safe existing
folder, writable only for ordinary file sources on capable hosts. Generated,
mirrored and exported sources remain read-only. Repeating an identical exact
connection is idempotent; reads/resolve never create one.

The existing descriptor-relative traversal, no-follow path checks, pinned root
identity, protected control/credential paths, bounded secret scanning, plain
metadata requirements and optimistic content revisions remain authoritative.
Root selection is not permission to access arbitrary paths outside that root.
Windows/hosts without secure traversal do not gain a weakened fallback.

Native and Link use the **same grant registry and `wiki.lock`**, preventing
independent authorities from creating racing overlapping roots. Cross-profile,
cross-principal and non-exact overlaps remain denied. An exact existing Link
root yields `WIKI_AUTHORITY_CONFLICT`409: explicitly remove the existing Link
connection using the existing host operation, then reconnect natively if desired.
There is no automatic adoption, upgrade, file deletion or ownership migration.
Existing legacy connections and recovery material are not relabeled native.

## Explicit Disconnect

`native-wiki-disconnect-v1` separately advertises `disconnect`. Invoke it only
after an explicit user Disconnect action, never automatic logout or local cache
clearing. It removes this principal/profile's connection across its devices,
not Hermes login, a Link connection, physical files, or the upload/recovery
journal. An unavailable source folder does not prevent registry removal.

Disconnect shares the same lock as upload commit. A commit holding the lock
finishes before disconnect; a commit admitted after disconnect cannot access
the retired grant. Immutable owner-scoped receipts retain the old Wiki ID and
generation. The same principal/profile receives the same success on retry;
unknown or wrong-principal/profile IDs return indistinguishable 404
`WIKI_NOT_ALLOWED`. At 1024 retained native receipts, new disconnects explicitly
fail with 413 before removing access and require host-local maintenance.

Explicit reconnect allocates a fresh Wiki ID and generation. Retired IDs cannot
be allocated again or granted by the legacy host grant method. Old pending
operation IDs stay bound to their retired grant; reconnect cannot adopt or
silently execute them. No foreign key cascades delete source recovery data.

## Shared journal and compatibility

The atomic version-2 storage migration adds an explicit owner discriminant:
`link_device` or `native_principal`, plus principal identity. Native upload/save
rows have SQL NULL in the unused device column, never a fabricated device.
Legacy rows preserve device values, grants, generations and exact recovery
digests. The single shared lock spans registry checks, transactional journals
and filesystem replacement across service instances/processes.

Native uploads bind principal, profile, authority, grant generation, path,
base revision, operation ID and digest. A different device authenticated as the
same principal may resume/reconcile exactly that operation; a different
principal/profile or any mismatched immutable upload fails. Source/profile/root
identity is rechecked around I/O, and context is checked across awaits.

Database rebuild, copied rows, ownership constraints, triggers, foreign-key
validation and schema-version commit occur atomically. Failure rolls back the
migration without leaving temporary tables or changing recovery ownership.
Unknown schema versions fail closed. Updated plugin code keeps old Link/app wire
contracts intact; running a pre-migration plugin binary against version-2 storage
is **not a supported downgrade**, particularly its positional upload inserts.
Activate matching plugin code in all processes sharing this state before use.
No installation or activation is performed by this source change.

Cancellation, native auth expiry, disconnect or lost response is not proof that
a prior commit did not happen. Query `save/status` using the same operation ID
under a fresh valid context; do not create a new mutation identity. Interrupted
submitted uploads are indeterminate, not silently repeated. Native token
revocation controls future admission; the plugin does not claim stronger
instantaneous revocation or recall of already delivered bytes. Signing out of an
optional Loopdy account does not delete independent native-principal Wiki data.

## Errors and verification

Wiki errors retain `{error:{code,message,retryable,details}}`. Notable HTTP
statuses: malformed422, unsafe path400/404, owner/profile/operation mismatch404,
authority/conflict/stale revision409, read-only403, digest mismatch422,
unsupported secure traversal501, quota413, state/busy503. Native auth/context
errors remain401/412/428. Diagnostics are bounded and do not echo raw paths,
credentials, private data or internal exceptions.

Tests exercise actual stock-serve auth and native connect/save/status in a
synthetic home, same-principal cross-device partial uploads, wrong-principal
denial, no Link adoption, migration fault rollback/FKs/recovery, legacy pending
uploads/device checks, shared-lock concurrency, stale revisions, unsafe paths,
read-only sources and uncertain commit recovery. No real host mutation,
deployment, restart, cloud dependency or provider/model call is required.
