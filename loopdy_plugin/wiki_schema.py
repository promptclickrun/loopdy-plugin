"""Atomic owner-discriminant migration for the single shared Wiki journal."""
from __future__ import annotations

import sqlite3


SCHEMA_VERSION = 2
_OWNER = """
    owner_kind TEXT NOT NULL DEFAULT 'link_device'
        CHECK(owner_kind IN ('link_device','native_principal')),
    principal_id TEXT,
    CHECK((owner_kind='link_device' AND principal_id IS NULL)
       OR (owner_kind='native_principal' AND principal_id IS NOT NULL))
"""
_TABLES = {
    "wiki_grants": """
        wiki_id TEXT PRIMARY KEY, label TEXT NOT NULL, root TEXT NOT NULL,
        root_dev INTEGER NOT NULL, root_ino INTEGER NOT NULL,
        generation TEXT NOT NULL, authority_id TEXT NOT NULL,
        profile_id TEXT NOT NULL, device_ids TEXT NOT NULL,
        writable INTEGER NOT NULL CHECK(writable IN (0,1)), source_kind TEXT NOT NULL,
        access_scope TEXT NOT NULL DEFAULT 'device'
            CHECK(access_scope IN ('device','account','native_principal')),
    """ + _OWNER + """,
        CHECK((owner_kind='link_device' AND access_scope IN ('device','account'))
           OR (owner_kind='native_principal' AND access_scope='native_principal' AND device_ids='[]'))
    """,
    "wiki_operations": """
        operation_id TEXT PRIMARY KEY, wiki_id TEXT NOT NULL,
        generation TEXT NOT NULL, authority_id TEXT NOT NULL,
        profile_id TEXT NOT NULL, device_id TEXT,
        path TEXT NOT NULL, base_revision TEXT NOT NULL,
        request_digest TEXT NOT NULL, proposed BLOB NOT NULL,
        base BLOB, observed BLOB NOT NULL, temp_name TEXT NOT NULL,
        reserved_bytes INTEGER NOT NULL, created_at INTEGER NOT NULL,
    """ + _OWNER + """,
        CHECK((owner_kind='link_device' AND device_id IS NOT NULL)
           OR (owner_kind='native_principal' AND device_id IS NULL))
    """,
    "wiki_uploads": """
        operation_id TEXT PRIMARY KEY, authority_id TEXT NOT NULL,
        profile_id TEXT NOT NULL, device_id TEXT,
        wiki_id TEXT NOT NULL, generation TEXT NOT NULL, path TEXT NOT NULL,
        base_revision TEXT NOT NULL, total_bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL, binding TEXT NOT NULL,
        content BLOB NOT NULL, submitted INTEGER NOT NULL CHECK(submitted IN (0,1)),
        created_at INTEGER NOT NULL,
    """ + _OWNER + """,
        CHECK((owner_kind='link_device' AND device_id IS NOT NULL)
           OR (owner_kind='native_principal' AND device_id IS NULL))
    """,
}


def migrate_owner_schema(connection: sqlite3.Connection) -> None:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version == SCHEMA_VERSION:
        return
    if version != 0 or connection.in_transaction:
        raise sqlite3.DatabaseError("Unsupported Wiki schema state")
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        for table, definition in _TABLES.items():
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            if "owner_kind" in columns or "principal_id" in columns:
                raise sqlite3.DatabaseError("Ambiguous Wiki ownership schema")
            connection.execute(f"CREATE TABLE {table}_owner_v2 ({definition})")
            if columns:
                # Names are schema-derived but must be the expected fixed columns.
                expected = {row[1] for row in connection.execute(f"PRAGMA table_info({table}_owner_v2)")}
                if set(columns) != expected - {"owner_kind", "principal_id"}:
                    raise sqlite3.DatabaseError("Unsupported Wiki columns")
                names = ",".join('"' + name + '"' for name in columns)
                connection.execute(f"INSERT INTO {table}_owner_v2 ({names}) SELECT {names} FROM {table}")
                connection.execute(f"DROP TABLE {table}")
            connection.execute(f"ALTER TABLE {table}_owner_v2 RENAME TO {table}")
        for action in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER wiki_operations_no_{action.lower()} BEFORE {action} "
                "ON wiki_operations BEGIN SELECT RAISE(ABORT, 'immutable Wiki recovery'); END"
            )
        connection.execute("""
            CREATE TRIGGER wiki_upload_binding_immutable
            BEFORE UPDATE OF operation_id,authority_id,profile_id,device_id,wiki_id,
                generation,path,base_revision,total_bytes,sha256,binding,created_at,owner_kind,principal_id
            ON wiki_uploads BEGIN SELECT RAISE(ABORT, 'immutable Wiki upload binding'); END
        """)
        connection.execute("""
            CREATE TRIGGER wiki_upload_submitted_monotonic
            BEFORE UPDATE OF submitted ON wiki_uploads WHEN OLD.submitted=1 AND NEW.submitted!=1
            BEGIN SELECT RAISE(ABORT, 'immutable Wiki submission'); END
        """)
        connection.execute("""
            CREATE TRIGGER wiki_upload_submitted_content
            BEFORE UPDATE OF content ON wiki_uploads WHEN OLD.submitted=1
            BEGIN SELECT RAISE(ABORT, 'immutable submitted Wiki bytes'); END
        """)
        connection.execute("""
            CREATE TABLE wiki_native_disconnects (
                wiki_id TEXT PRIMARY KEY, authority_id TEXT NOT NULL,
                profile_id TEXT NOT NULL, principal_id TEXT NOT NULL,
                generation TEXT NOT NULL, created_at INTEGER NOT NULL
            )
        """)
        for action in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER wiki_native_disconnects_no_{action.lower()} BEFORE {action} "
                "ON wiki_native_disconnects BEGIN SELECT RAISE(ABORT, 'immutable Wiki disconnect'); END"
            )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise sqlite3.DatabaseError("Wiki recovery references are inconsistent")
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")
