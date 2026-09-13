"""Pre-native Wiki schemas for migration tests, independent of v2 definitions."""

LEGACY_TABLES = {
    "wiki_grants": """wiki_id TEXT PRIMARY KEY,label TEXT NOT NULL,root TEXT NOT NULL,
        root_dev INTEGER NOT NULL,root_ino INTEGER NOT NULL,generation TEXT NOT NULL,
        authority_id TEXT NOT NULL,profile_id TEXT NOT NULL,device_ids TEXT NOT NULL,
        writable INTEGER NOT NULL CHECK(writable IN(0,1)),source_kind TEXT NOT NULL""",
    "wiki_operations": """operation_id TEXT PRIMARY KEY,wiki_id TEXT NOT NULL,generation TEXT NOT NULL,
        authority_id TEXT NOT NULL,profile_id TEXT NOT NULL,device_id TEXT NOT NULL,path TEXT NOT NULL,
        base_revision TEXT NOT NULL,request_digest TEXT NOT NULL,proposed BLOB NOT NULL,base BLOB,
        observed BLOB NOT NULL,temp_name TEXT NOT NULL,reserved_bytes INTEGER NOT NULL,created_at INTEGER NOT NULL""",
    "wiki_uploads": """operation_id TEXT PRIMARY KEY,authority_id TEXT NOT NULL,profile_id TEXT NOT NULL,
        device_id TEXT NOT NULL,wiki_id TEXT NOT NULL,generation TEXT NOT NULL,path TEXT NOT NULL,
        base_revision TEXT NOT NULL,total_bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,binding TEXT NOT NULL,
        content BLOB NOT NULL,submitted INTEGER NOT NULL CHECK(submitted IN(0,1)),created_at INTEGER NOT NULL""",
}


def restore_legacy_schema(connection, *, omit_access_scope=False):
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute("DROP TABLE IF EXISTS wiki_native_disconnects")
        for table, definition in LEGACY_TABLES.items():
            if table == "wiki_grants" and not omit_access_scope:
                definition += ",access_scope TEXT NOT NULL DEFAULT 'device' CHECK(access_scope IN('device','account'))"
            connection.execute(f"CREATE TABLE {table}_legacy_fixture ({definition})")
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table}_legacy_fixture)")]
            names = ",".join(columns)
            connection.execute(f"INSERT INTO {table}_legacy_fixture ({names}) SELECT {names} FROM {table}")
            connection.execute(f"DROP TABLE {table}")
            connection.execute(f"ALTER TABLE {table}_legacy_fixture RENAME TO {table}")
        connection.execute("PRAGMA user_version=0")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")
