"""An agent's board in the bighelp app: Feed posts, Ideas and Goals, plus the
Activity and Approvals history shown on its profile.

Nothing here calls a model or schedules work. Agents write to the board with the
``bighelp_board`` tool only when a user has asked for that kind of update (the
bundled ``bighelp-feed-and-ideas`` skill explains how). Activity and approval
rows are recorded from lifecycle hooks the agent already fires.

Each profile keeps its own database under its Hermes home, so a turn that runs
in the gateway and a read served by the dashboard see the same rows.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CAPABILITY = "native-agent-board-v1"
TOOL_NAME = "bighelp_board"
KINDS = ("feed", "idea", "goal")
GOAL_SECTIONS = ("tracking", "goal")
GOAL_STATUSES = ("active", "done")
MAX_TITLE = 200
MAX_BODY = 4_000
MAX_NOTE = 600
MAX_ICON = 16
MAX_SECTION = 60
MAX_IMAGES = 6
MAX_LINKS = 8
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_ITEMS_PER_KIND = 500
MAX_ACTIVITY = 1_000
MAX_APPROVALS = 1_000
_ITEM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_IMAGE_TYPES = (
    (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
    (b"\xff\xd8\xff", "image/jpeg", "jpg"),
    (b"GIF87a", "image/gif", "gif"),
    (b"GIF89a", "image/gif", "gif"),
)


class BoardError(ValueError):
    """A request the board refuses; the message is safe to show the agent."""


def _clean(value: Any, limit: int, *, field: str, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise BoardError(f"{field} must be text.")
    text = value.strip()
    if required and not text:
        raise BoardError(f"{field} is required.")
    if len(text) > limit:
        raise BoardError(f"{field} is longer than {limit} characters.")
    return text


def _image_type(head: bytes) -> tuple[str, str] | None:
    for magic, mime, extension in _IMAGE_TYPES:
        if head.startswith(magic):
            return mime, extension
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp", "webp"
    if head[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftypmsf1"):
        return "image/heic", "heic"
    return None


class BoardStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.media = directory / "board-media"
        self.path = directory / "board.sqlite3"
        self._lock = threading.RLock()
        directory.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS items(
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL,
                    body TEXT NOT NULL DEFAULT '', icon TEXT NOT NULL DEFAULT '',
                    section TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '', links TEXT NOT NULL DEFAULT '[]',
                    images TEXT NOT NULL DEFAULT '[]', source TEXT NOT NULL DEFAULT '',
                    liked INTEGER NOT NULL DEFAULT 0, dismissed INTEGER NOT NULL DEFAULT 0,
                    created REAL NOT NULL, updated REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS items_kind ON items(kind, created DESC);
                CREATE TABLE IF NOT EXISTS activity(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL DEFAULT '', request TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
                    tools TEXT NOT NULL DEFAULT '[]', outcome TEXT NOT NULL DEFAULT '',
                    created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS approvals(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '', command TEXT NOT NULL DEFAULT '',
                    choice TEXT NOT NULL DEFAULT '', created REAL NOT NULL);
            """)

    @contextmanager
    def _db(self):
        with self._lock:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.execute("PRAGMA journal_mode=WAL")
                yield db
                db.commit()
            finally:
                db.close()

    # MARK: Items

    def publish(self, kind: str, *, title: Any, body: Any = "", icon: Any = "", section: Any = "",
                links: Any = None, images: Any = None, source: Any = "", item_id: Any = None,
                note: Any = "", status: Any = None, now: float | None = None) -> dict:
        if kind not in KINDS:
            raise BoardError("kind must be feed, idea or goal.")
        now = time.time() if now is None else now
        title = _clean(title, MAX_TITLE, field="title", required=True)
        body = _clean(body, MAX_BODY, field="body")
        icon = _clean(icon, MAX_ICON, field="icon")
        section = _clean(section, MAX_SECTION, field="section")
        note = _clean(note, MAX_NOTE, field="note")
        source = _clean(source, 200, field="source")
        if kind == "goal":
            section = section.lower() or "goal"
            if section not in GOAL_SECTIONS:
                raise BoardError("A goal's section must be tracking or goal.")
            status = (status or "active").lower()
            if status not in GOAL_STATUSES:
                raise BoardError("A goal's status must be active or done.")
        else:
            status = ""
        link_rows = self._links(links)
        if item_id is not None:
            item_id = _clean(item_id, 64, field="id", required=True)
            if not _ITEM_ID.fullmatch(item_id):
                raise BoardError("id may use letters, digits, dot, dash and underscore.")
        else:
            item_id = uuid.uuid4().hex
        image_rows = self._store_images(item_id, images)
        with self._db() as db:
            existing = db.execute("SELECT kind, created FROM items WHERE id=?", (item_id,)).fetchone()
            if existing and existing["kind"] != kind:
                raise BoardError("That id belongs to a different kind of item.")
            created = existing["created"] if existing else now
            db.execute("""INSERT INTO items(id,kind,title,body,icon,section,status,note,links,images,source,created,updated)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                          ON CONFLICT(id) DO UPDATE SET title=excluded.title, body=excluded.body,
                            icon=excluded.icon, section=excluded.section, status=excluded.status,
                            note=excluded.note, links=excluded.links,
                            images=CASE WHEN excluded.images='[]' THEN items.images ELSE excluded.images END,
                            source=excluded.source, dismissed=0, updated=excluded.updated""",
                       (item_id, kind, title, body, icon, section, status, note,
                        json.dumps(link_rows), json.dumps(image_rows), source, created, now))
            self._prune(db, kind)
            return self._item(db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())

    def update_goal(self, item_id: Any, *, note: Any = None, status: Any = None,
                    now: float | None = None) -> dict:
        item_id = _clean(item_id, 64, field="id", required=True)
        with self._db() as db:
            row = db.execute("SELECT * FROM items WHERE id=? AND kind='goal'", (item_id,)).fetchone()
            if row is None:
                raise BoardError("No goal has that id. List goals to find it.")
            next_note = row["note"] if note is None else _clean(note, MAX_NOTE, field="note")
            next_status = row["status"] if status is None else str(status).lower()
            if next_status not in GOAL_STATUSES:
                raise BoardError("A goal's status must be active or done.")
            db.execute("UPDATE items SET note=?, status=?, updated=? WHERE id=?",
                       (next_note, next_status, time.time() if now is None else now, item_id))
            return self._item(db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())

    def set_flags(self, item_id: str, *, liked: bool | None = None, dismissed: bool | None = None,
                  status: str | None = None) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise BoardError("That item no longer exists.")
            if status is not None and (row["kind"] != "goal" or status not in GOAL_STATUSES):
                raise BoardError("Only goals have a status.")
            db.execute("UPDATE items SET liked=?, dismissed=?, status=?, updated=? WHERE id=?", (
                int(row["liked"] if liked is None else liked),
                int(row["dismissed"] if dismissed is None else dismissed),
                row["status"] if status is None else status, time.time(), item_id))
            return self._item(db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())

    def remove(self, item_id: Any) -> bool:
        item_id = _clean(item_id, 64, field="id", required=True)
        with self._db() as db:
            removed = db.execute("DELETE FROM items WHERE id=?", (item_id,)).rowcount > 0
        for file in self.media.glob(f"{item_id}-*"):
            file.unlink(missing_ok=True)
        return removed

    def items(self, kinds: tuple[str, ...] = KINDS, *, limit: int = 100,
              include_dismissed: bool = False) -> list[dict]:
        kinds = tuple(kind for kind in kinds if kind in KINDS) or KINDS
        limit = max(1, min(int(limit), 200))
        placeholders = ",".join("?" for _ in kinds)
        where = f"kind IN ({placeholders})" + ("" if include_dismissed else " AND dismissed=0")
        with self._db() as db:
            rows = db.execute(f"SELECT * FROM items WHERE {where} ORDER BY created DESC LIMIT ?",
                              (*kinds, limit)).fetchall()
            return [self._item(row) for row in rows]

    def image(self, item_id: str, index: int) -> tuple[str, bytes]:
        with self._db() as db:
            row = db.execute("SELECT images FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise BoardError("That item no longer exists.")
        images = json.loads(row["images"])
        if not 0 <= index < len(images) or images[index].get("file") is None:
            raise BoardError("That image is not stored on this computer.")
        path = self.media / images[index]["file"]
        data = path.read_bytes()
        kind = _image_type(data[:16])
        if kind is None:
            raise BoardError("That image is not stored on this computer.")
        return kind[0], data

    @staticmethod
    def _links(links: Any) -> list[dict]:
        if links in (None, ""):
            return []
        if not isinstance(links, list) or len(links) > MAX_LINKS:
            raise BoardError(f"links must be a list of at most {MAX_LINKS}.")
        rows = []
        for link in links:
            if isinstance(link, str):
                link = {"url": link}
            if not isinstance(link, dict):
                raise BoardError("Each link needs a url.")
            url = _clean(link.get("url"), 2_000, field="link url", required=True)
            if not url.startswith(("https://", "http://")):
                raise BoardError("Links must be http or https URLs.")
            rows.append({"url": url, "title": _clean(link.get("title"), MAX_TITLE, field="link title")})
        return rows

    def _store_images(self, item_id: str, images: Any) -> list[dict]:
        if images in (None, ""):
            return []
        if not isinstance(images, list) or len(images) > MAX_IMAGES:
            raise BoardError(f"images must be a list of at most {MAX_IMAGES}.")
        rows: list[dict] = []
        for index, image in enumerate(images):
            if not isinstance(image, str) or not image.strip():
                raise BoardError("Each image is a file path or an https URL.")
            image = image.strip()
            if image.startswith("https://"):
                if len(image) > 2_000:
                    raise BoardError("An image URL is too long.")
                rows.append({"url": image})
                continue
            # A copy keeps the post intact after caches are cleaned, and the app
            # can only ever read these copies, never an arbitrary path.
            source = Path(image).expanduser()
            if not source.is_absolute() or not source.is_file():
                raise BoardError(f"Image {index + 1} is not a file on this computer.")
            if source.stat().st_size > MAX_IMAGE_BYTES:
                raise BoardError(f"Image {index + 1} is larger than 8 MB.")
            data = source.read_bytes()
            kind = _image_type(data[:16])
            if kind is None:
                raise BoardError(f"Image {index + 1} is not a PNG, JPEG, GIF, WebP or HEIC image.")
            self.media.mkdir(parents=True, exist_ok=True)
            name = f"{item_id}-{index}.{kind[1]}"
            (self.media / name).write_bytes(data)
            rows.append({"file": name, "mimeType": kind[0]})
        return rows

    def _prune(self, db, kind: str) -> None:
        stale = db.execute("SELECT id FROM items WHERE kind=? ORDER BY created DESC LIMIT -1 OFFSET ?",
                           (kind, MAX_ITEMS_PER_KIND)).fetchall()
        for row in stale:
            db.execute("DELETE FROM items WHERE id=?", (row["id"],))
            for file in self.media.glob(f"{row['id']}-*"):
                file.unlink(missing_ok=True)

    @staticmethod
    def _item(row) -> dict:
        images = []
        for index, image in enumerate(json.loads(row["images"])):
            images.append({"url": image["url"]} if "url" in image
                          else {"index": index, "mimeType": image.get("mimeType", "")})
        return {
            "id": row["id"], "kind": row["kind"], "title": row["title"], "body": row["body"],
            "icon": row["icon"], "section": row["section"], "status": row["status"], "note": row["note"],
            "links": json.loads(row["links"]), "images": images, "source": row["source"],
            "liked": bool(row["liked"]), "dismissed": bool(row["dismissed"]),
            "createdAt": int(row["created"]), "updatedAt": int(row["updated"]),
        }

    # MARK: Activity and approvals

    def record_activity(self, *, session_id: str, turn_id: str, request: str, summary: str,
                        category: str, tools: list[str], outcome: str, now: float | None = None) -> None:
        with self._db() as db:
            db.execute("""INSERT INTO activity(session_id,turn_id,request,summary,category,tools,outcome,created)
                          VALUES(?,?,?,?,?,?,?,?)""",
                       (session_id, turn_id, request[:400], summary[:400], category,
                        json.dumps(tools[:40]), outcome, time.time() if now is None else now))
            db.execute("DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY id DESC LIMIT ?)",
                       (MAX_ACTIVITY,))

    def activity(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with self._db() as db:
            rows = db.execute("SELECT * FROM activity ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": row["id"], "sessionId": row["session_id"], "request": row["request"],
                 "summary": row["summary"], "category": row["category"], "tools": json.loads(row["tools"]),
                 "outcome": row["outcome"], "createdAt": int(row["created"])} for row in rows]

    def record_approval(self, *, session_id: str, description: str, command: str, choice: str,
                        now: float | None = None) -> None:
        with self._db() as db:
            db.execute("INSERT INTO approvals(session_id,description,command,choice,created) VALUES(?,?,?,?,?)",
                       (session_id, description[:300], command[:300], choice[:40],
                        time.time() if now is None else now))
            db.execute("DELETE FROM approvals WHERE id NOT IN (SELECT id FROM approvals ORDER BY id DESC LIMIT ?)",
                       (MAX_APPROVALS,))

    def approvals(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with self._db() as db:
            rows = db.execute("SELECT * FROM approvals ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": row["id"], "sessionId": row["session_id"], "description": row["description"],
                 "command": row["command"], "choice": row["choice"], "createdAt": int(row["created"])}
                for row in rows]


_stores: dict[str, BoardStore] = {}
_stores_lock = threading.Lock()


def store_for_home(home: Path) -> BoardStore:
    directory = (home / "plugin-data" / "loopdy").resolve()
    with _stores_lock:
        store = _stores.get(str(directory))
        if store is None:
            store = BoardStore(directory)
            _stores[str(directory)] = store
        return store


def current_store() -> BoardStore:
    """The store of the profile whose turn is running (context-local home)."""
    from hermes_constants import get_hermes_home
    return store_for_home(get_hermes_home())


def store_for_profile(profile: str) -> BoardStore:
    from hermes_cli.profiles import get_profile_dir
    return store_for_home(get_profile_dir(profile))


def available() -> bool:
    try:
        from hermes_cli.profiles import get_profile_dir  # noqa: F401
        from hermes_constants import get_hermes_home  # noqa: F401
    except ImportError:
        return False
    return True


def session_titles(profile: str, session_ids: list[str]) -> dict[str, str]:
    """Hermes' own session titles, read-only, for activity rows."""
    if not session_ids:
        return {}
    from hermes_cli.profiles import get_profile_dir
    path = get_profile_dir(profile) / "state.db"
    if not path.is_file():
        return {}
    ids = list(dict.fromkeys(session_ids))[:200]
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        try:
            rows = db.execute(f"SELECT id, title FROM sessions WHERE id IN ({','.join('?' for _ in ids)})",
                              ids).fetchall()
        finally:
            db.close()
    except sqlite3.Error:
        return {}
    return {row[0]: row[1] for row in rows if isinstance(row[1], str) and row[1].strip()}


# MARK: Tool

TOOL_DESCRIPTION = (
    "Publish to the user's bighelp app. Actions: 'post' adds a Feed post (a briefing, news item or "
    "update with optional images and links); 'idea' proposes something you could do for the user; "
    "'goal' adds or updates a Goal (section 'tracking' for things you watch, 'goal' for the user's "
    "own goals) with a short status note; 'update_goal' changes a goal's note or marks it done; "
    "'list' shows recent items so you can update rather than duplicate; 'remove' deletes one. "
    "Only publish what the user asked you to surface. Never create schedules or posts on your own "
    "initiative; see the bighelp-feed-and-ideas skill."
)

TOOL_PARAMETERS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action": {"type": "string", "enum": ["post", "idea", "goal", "update_goal", "list", "remove"]},
        "id": {"type": "string", "maxLength": 64,
               "description": "Stable id to update an existing goal or idea instead of adding a new one."},
        "title": {"type": "string", "maxLength": MAX_TITLE},
        "body": {"type": "string", "maxLength": MAX_BODY,
                 "description": "Markdown. Keep Feed posts to a short paragraph; ideas explain the offer."},
        "icon": {"type": "string", "maxLength": MAX_ICON, "description": "One emoji that fits the item."},
        "section": {"type": "string", "maxLength": MAX_SECTION,
                    "description": "Ideas: a short category like Health or Shopping. Goals: tracking or goal."},
        "note": {"type": "string", "maxLength": MAX_NOTE, "description": "A goal's latest status in one line."},
        "status": {"type": "string", "enum": list(GOAL_STATUSES)},
        "images": {"type": "array", "maxItems": MAX_IMAGES, "items": {"type": "string"},
                   "description": "Absolute image file paths on this computer or https URLs."},
        "links": {"type": "array", "maxItems": MAX_LINKS, "items": {"type": "object", "properties": {
            "url": {"type": "string"}, "title": {"type": "string"}}, "required": ["url"]}},
        "kind": {"type": "string", "enum": list(KINDS), "description": "For list: which items to show."},
        "source": {"type": "string", "maxLength": 200,
                   "description": "Which automation or request produced this, e.g. 'Evening AI news'."},
    },
    "required": ["action"],
}


def handle_tool(args: dict, store: BoardStore | None = None) -> str:
    store = store or current_store()
    action = args.get("action")
    try:
        if action == "post":
            item = store.publish("feed", title=args.get("title"), body=args.get("body"), icon=args.get("icon"),
                                 links=args.get("links"), images=args.get("images"), source=args.get("source"))
        elif action == "idea":
            item = store.publish("idea", title=args.get("title"), body=args.get("body"), icon=args.get("icon"),
                                 section=args.get("section"), links=args.get("links"),
                                 source=args.get("source"), item_id=args.get("id"))
        elif action == "goal":
            item = store.publish("goal", title=args.get("title"), body=args.get("body"), icon=args.get("icon"),
                                 section=args.get("section"), note=args.get("note"), status=args.get("status"),
                                 source=args.get("source"), item_id=args.get("id"))
        elif action == "update_goal":
            item = store.update_goal(args.get("id"), note=args.get("note"), status=args.get("status"))
        elif action == "list":
            kind = args.get("kind")
            items = store.items((kind,) if kind in KINDS else KINDS, limit=30, include_dismissed=False)
            return json.dumps({"items": [{key: item[key] for key in
                               ("id", "kind", "title", "section", "status", "note", "createdAt")}
                               for item in items]})
        elif action == "remove":
            return json.dumps({"removed": store.remove(args.get("id"))})
        else:
            raise BoardError("action must be post, idea, goal, update_goal, list or remove.")
    except BoardError as error:
        return json.dumps({"error": str(error)})
    return json.dumps({"ok": True, "id": item["id"], "kind": item["kind"],
                       "shownIn": {"feed": "Feed", "idea": "Ideas", "goal": "Goals"}[item["kind"]]})


# MARK: Hooks

_TOOL_CATEGORIES = (
    ("images", ("image_generate", "video", "image", "mixture_of")),
    ("coding", ("terminal", "execute_code", "process", "patch", "code")),
    ("web", ("web_search", "web_extract", "browser", "search_web", "fetch")),
    ("seeing", ("vision",)),
    ("memory", ("memory", "session_search", "skill")),
    ("scheduling", ("cronjob", "schedule", "cron")),
    ("delegating", ("delegate", "subagent")),
    ("files", ("read_file", "write_file", "search_files", "file")),
    ("messaging", ("send_message", "text_to_speech", "tts")),
    ("publishing", (TOOL_NAME,)),
)


def tool_category(name: str) -> str:
    lowered = name.lower()
    for category, markers in _TOOL_CATEGORIES:
        if any(marker in lowered for marker in markers):
            return category
    return "tools"


def _first_sentence(text: Any, limit: int = 180) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r"`{3}.*?`{3}", " ", text, flags=re.S)
    text = " ".join(re.sub(r"[#*_>`\[\]]", " ", text).split())
    match = re.match(r"(.+?[.!?])(\s|$)", text)
    sentence = match.group(1) if match else text
    return sentence if len(sentence) <= limit else sentence[: limit - 1].rstrip() + "…"


class ActivityRecorder:
    """Per-process turn buffers; a turn starts and ends in the same process."""

    def __init__(self, store_getter=current_store):
        self._turns: OrderedDict[tuple[str, str], dict] = OrderedDict()
        self._lock = threading.Lock()
        self._store_getter = store_getter

    def observe(self, hook: str, **payload: Any) -> None:
        try:
            self._observe(hook, **payload)
        except Exception as error:  # observability must never break a turn
            logger.debug("bighelp board observer skipped %s: %s", hook, type(error).__name__)

    def _observe(self, hook: str, **payload: Any) -> None:
        if payload.get("parent_session_id") or payload.get("platform") == "subagent":
            return
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return
        if hook == "post_approval_response":
            choice = payload.get("choice")
            if isinstance(choice, str) and choice:
                self._store_getter().record_approval(
                    session_id=session_id, description=str(payload.get("description") or ""),
                    command=str(payload.get("command") or ""), choice=choice)
            return
        turn_id = payload.get("turn_id") if isinstance(payload.get("turn_id"), str) else ""
        key = (session_id, turn_id)
        with self._lock:
            if hook == "pre_llm_call":
                message = payload.get("user_message")
                if key not in self._turns:
                    self._turns[key] = {"request": _first_sentence(message, 200) if isinstance(message, str)
                                        else "", "tools": [], "response": ""}
                    while len(self._turns) > 64:
                        self._turns.popitem(last=False)
                return
            turn = self._turns.get(key) or self._turns.get((session_id, ""))
            if turn is None:
                return
            if hook == "post_tool_call" and isinstance(payload.get("tool_name"), str):
                if len(turn["tools"]) < 200:
                    turn["tools"].append(payload["tool_name"])
                return
            if hook == "post_llm_call" and isinstance(payload.get("assistant_response"), str):
                turn["response"] = payload["assistant_response"]
                return
            if hook != "on_session_end":
                return
            self._turns.pop(key, None)
        # Only turns that did something become activity; plain chat stays in the chat.
        tools = [name for name in turn["tools"] if name != TOOL_NAME] or turn["tools"]
        if not tools:
            return
        counts: dict[str, int] = {}
        for name in tools:
            category = tool_category(name)
            counts[category] = counts.get(category, 0) + 1
        category = max(counts, key=lambda value: (counts[value], value != "tools"))
        outcome = ("stopped" if payload.get("interrupted") is True
                   else "failed" if payload.get("failed") is True else "done")
        self._store_getter().record_activity(
            session_id=session_id, turn_id=turn_id, request=turn["request"],
            summary=_first_sentence(turn["response"]), category=category,
            tools=list(dict.fromkeys(tools)), outcome=outcome)


def register(ctx: Any) -> None:
    """Register the board tool and its activity/approval observers."""
    ctx.register_tool(
        name=TOOL_NAME, toolset="loopdy",
        schema={"name": TOOL_NAME, "description": TOOL_DESCRIPTION, "parameters": TOOL_PARAMETERS},
        handler=lambda args, **_: handle_tool(args), emoji="📌",
    )
    recorder = ActivityRecorder()
    for hook in ("pre_llm_call", "post_tool_call", "post_llm_call", "on_session_end", "post_approval_response"):
        ctx.register_hook(hook, lambda _hook=hook, **payload: recorder.observe(_hook, **payload))
    skill = Path(__file__).resolve().parents[1] / "skills" / "bighelp-feed-and-ideas" / "SKILL.md"
    description = ("Use when the user wants regular updates, briefings, news, ideas or goal tracking "
                   "surfaced in the bighelp app's Feed, Ideas or Goals.")
    ctx.register_skill("bighelp-feed-and-ideas", skill, description=description,
                       frontmatter={"name": "bighelp-feed-and-ideas", "description": description})


def media_payload(mime: str, data: bytes) -> dict:
    return {"mimeType": mime, "data": base64.b64encode(data).decode("ascii"), "byteCount": len(data)}
