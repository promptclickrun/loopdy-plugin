# Account-authorized Wiki connect

No wire change: app Save calls `wiki.connect` with `agentId` and canonical absolute `folderPath`, under the current authenticated Link target context. No account ID, writable flag, or approval token is accepted from the payload.

Only explicit connect creates/converts a grant. The encrypted relay/account-key boundary and current host/epoch authority authorize a durable paired-account connection. Same-account replacement device IDs can reconnect and read/write without host CLI approval. The client should retain only inert folder selection keyed by stable account + host + profile, reconnect under fresh authority, and discard stale revisions after grant generation changes.

Existing exact file grants convert to account read/write on explicit connect, retaining wiki ID/root/inode/label/profile/source kind and rotating generation once. Reads/roots/resolve do not convert other grants. Generated/mirror/export sources remain read-only. Save/upload operation ownership remains per device; reconnect does not resume another device's in-flight operation.

Authority remains pinned to relay origin, account-key fingerprint, host ID and host authorization epoch. Another account or changed pairing authority cannot adopt existing roots. Profile overlap, non-exact overlap, ambiguous roots, replaced inodes, symlinks, traversal and system/credential roots fail closed. A custom persistence home may contain ordinary Wiki directories; the home itself, ancestors, host control subtrees and hidden control roots cannot be selected.

SQLite `access_scope` is additive with legacy `device` default, compatible with installed account-grant storage. No runtime install, live state migration or host restart is part of this change. Revoking a connection removes its grant; an authenticated account may explicitly connect it again (revocation is not an account access ban).
