"""On-demand, disposable in-memory Wiki index; never writes source to disk.

Rebuild on every search (including pagination), validate source revisions after
scanning, then discard. There is deliberately no startup scan, global provider
search, cross-grant cache, or cached result served without authorization.
"""
from __future__ import annotations

import base64
import json
import time
from collections import deque
from pathlib import Path

from .wiki_contract import MAX_PAYLOAD_BYTES, validate_payload
from .wiki_service import WikiService, _Reader
from .workspace_files import WorkspaceFilesError

MAX_DOCUMENTS = 256
MAX_DIRECTORIES = 128
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_BYTES = 65_536
MAX_SCAN_SECONDS = 3.0


class WikiSearch:
    def __init__(self, service: WikiService):
        self.service = service

    def search(self, payload: dict, *, device_id: str) -> dict:
        p = validate_payload("wiki.search", payload)
        with self.service._locked() as connection:
            grant = self.service._authorize(connection, p["wikiId"], p["agentId"], device_id)
            reader = _Reader(self.service, connection, grant)
            # This request-local index resides in process memory, outside roots;
            # only secret-scanned names/UTF-8 content can enter it.
            index, directories = [], []
            pending = deque([""])
            complete, used = True, 0
            deadline = time.monotonic() + MAX_SCAN_SECONDS
            while pending:
                if len(directories) >= MAX_DIRECTORIES or time.monotonic() >= deadline:
                    complete = False
                    break
                path = pending.popleft()
                try:
                    listing = reader.list_directory(p["wikiId"], path=path, limit=100)
                except WorkspaceFilesError as error:
                    if error.code in {"DIRECTORY_OVERSIZED", "PATH_NOT_FOUND", "INVALID_PATH"}:
                        complete = False
                        continue
                    raise
                directories.append((path, listing["revision"]))
                if listing["next_offset"] is not None:
                    complete = False
                for entry in listing["entries"]:
                    if entry["kind"] == "directory":
                        if len(pending) + len(directories) < MAX_DIRECTORIES and entry["path"].count("/") < 32:
                            pending.append(entry["path"])
                        else:
                            complete = False
                        continue
                    if (len(index) >= MAX_DOCUMENTS or entry["size"] > MAX_DOCUMENT_BYTES
                            or used + entry["size"] > MAX_INDEX_BYTES or time.monotonic() >= deadline):
                        complete = False
                        continue
                    try:
                        document = reader.read_file(p["wikiId"], path=entry["path"], limit=MAX_DOCUMENT_BYTES)
                    except WorkspaceFilesError as error:
                        if error.code in {"SECRET_SCAN_BLOCKED", "PATH_PROTECTED", "PATH_NOT_FOUND", "INVALID_PATH", "HARD_LINK_UNSAFE"}:
                            complete = False
                            continue
                        raise
                    # A source can grow since listing. Never call a partial page indexed.
                    if (document["availability"] == "oversized" or document["next_offset"] is not None
                            or (p["mode"] == "content" and document["availability"] != "available")):
                        complete = False
                        continue
                    content = base64.b64decode(document["data"], validate=True)
                    if used + len(content) > MAX_INDEX_BYTES:
                        complete = False
                        continue
                    text = content.decode("utf-8", "strict") if document["availability"] == "available" else ""
                    used += len(content)
                    index.append((entry["path"], document["revision"], text))
            # Invalidate on any scanned directory or document change. Cached
            # bytes never outlive this request. This is optimistic, not FS CAS.
            for path, revision in directories:
                reader.list_directory(p["wikiId"], path=path, limit=1, revision=revision)
            matches = []
            needle = p["query"].casefold()
            for path, revision, text in index:
                reader.read_file(p["wikiId"], path=path, limit=1, revision=revision)
                name = Path(path).name
                haystack = name if p["mode"] == "name" else text
                position = haystack.casefold().find(needle)
                if position < 0:
                    continue
                # Snippet is a bounded readable preview, never document authority.
                snippet = "" if p["mode"] == "name" else text[max(0, position - 80):position + 240]
                snippet = "".join(c for c in snippet if ord(c) >= 32 or c in "\n\r\t")
                matches.append({"path": path, "title": name, "snippet": snippet,
                                "revision": f"wiki-v1:{grant['generation']}:{revision.removeprefix('sha256:')}"})
            matches.sort(key=lambda item: (item["path"].casefold(), item["path"]))
            selected = matches[p["offset"]:p["offset"] + p["limit"]]
            result = {"wikiId": p["wikiId"], "query": p["query"], "mode": p["mode"],
                      "matches": selected, "nextOffset": None,
                      "isComplete": complete, "indexedAt": int(time.time())}
            while len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_PAYLOAD_BYTES - 256 and len(selected) > 1:
                selected.pop()
            if p["offset"] + len(selected) < len(matches):
                result["nextOffset"] = p["offset"] + len(selected)
            self.service._revalidate(connection, grant)
            return result
