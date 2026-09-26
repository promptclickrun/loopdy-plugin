"""Configured-workspace file projection for Loopdy native clients.

This module deliberately does not use Hermes' process cwd or its permissive
managed-files fallback. Every operation starts from the serving profile's raw,
absolute ``terminal.cwd`` and traverses below that canonical root.
"""
from __future__ import annotations

import base64
import ctypes
import heapq
import json
import math
import mimetypes
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from fastapi import Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .native_context import NativeAPIError, NativeContext, PROFILE_ID, native_context


CAPABILITY = "native-workspace-files-v1"
# Artifacts: the files the agent made or sent, newest first, in one request.
# A workspace can hold millions of files, so this never walks the whole tree:
# it reads the agent's own write_file/patch calls and MEDIA deliveries, then
# adds a shallow look at the top folders for anything made another way.
RECENT_CAPABILITY = "native-workspace-recent-v1"
RECENT_LIMIT = 300
RECENT_HISTORY_ROWS = 3_000
RECENT_SHALLOW_DEPTH = 2
RECENT_SHALLOW_DIRECTORIES = 400
RECENT_SHALLOW_SECONDS = 1.5
_RECENT_SKIPPED_NAMES = frozenset({
    "node_modules", "bower_components", "Pods", "Carthage", "DerivedData", "SourcePackages",
    "build", "dist", "target", "vendor", "venv", "env", "__pycache__", "site-packages",
    "coverage", "xcuserdata",
})
_RECENT_SKIPPED_SUFFIXES = (
    ".xcodeproj", ".xcworkspace", ".xcassets", ".xcarchive", ".xcresult", ".app", ".framework",
    ".xcframework", ".bundle", ".dSYM", ".photoslibrary", ".lproj",
)
# Housekeeping files, not things anyone made.
_RECENT_SKIPPED_EXTENSIONS = (
    ".log", ".pyc", ".pyo", ".o", ".a", ".class", ".tmp", ".swp", ".lock", ".pid",
    "-wal", "-shm", "-journal",
)
_WRITING_TOOLS = ("write_file", "patch")
MAX_BODY_BYTES = 8_192
MAX_LISTING_BYTES = 196_608
MAX_FILE_BYTES = 25 * 1_024 * 1_024
MAX_READ_RESPONSE_BYTES = ((MAX_FILE_BYTES + 2) // 3) * 4 + 8_192
MAX_ROWS = 2_000


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str | None = Field(default=None, max_length=4_096)


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _invalid_number(_: str) -> None:
    raise ValueError("invalid number")


def available() -> bool:
    if os.name == "nt" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return False
    try:
        from hermes_cli.config import read_user_config_raw
        from hermes_cli.profiles import get_profile_dir, profile_exists
    except ImportError:
        return False
    return all(callable(value) for value in (read_user_config_raw, get_profile_dir, profile_exists))


def _configured_root(profile_id: str | None) -> Path:
    if profile_id is None or PROFILE_ID.fullmatch(profile_id) is None:
        raise NativeAPIError(501, "workspace_identity_unavailable", "This host cannot identify its serving profile workspace.")
    try:
        from hermes_cli.config import read_user_config_raw
        from hermes_cli.profiles import get_profile_dir, profile_exists
    except ImportError:
        raise NativeAPIError(501, "workspace_files_unavailable", "Configured workspace files are unavailable on this host.") from None
    if not profile_exists(profile_id):
        raise NativeAPIError(409, "workspace_identity_changed", "The serving profile workspace changed; reconnect before retrying.")
    try:
        raw = read_user_config_raw(get_profile_dir(profile_id) / "config.yaml")
    except (OSError, UnicodeError, ValueError, TypeError):
        raise NativeAPIError(409, "workspace_config_invalid", "The serving profile configuration must be repaired locally.") from None
    terminal = raw.get("terminal")
    cwd = terminal.get("cwd") if isinstance(terminal, dict) else None
    if not isinstance(cwd, str) or not cwd.strip() or cwd.strip() in {".", "auto", "cwd"}:
        raise NativeAPIError(409, "workspace_not_configured", "Set an absolute terminal.cwd for this profile before opening workspace files.")
    try:
        candidate = Path(cwd).expanduser()
    except (OSError, RuntimeError, ValueError):
        raise NativeAPIError(409, "workspace_not_configured", "The serving profile requires an absolute terminal.cwd.") from None
    if not candidate.is_absolute():
        raise NativeAPIError(409, "workspace_not_configured", "The serving profile requires an absolute terminal.cwd.")
    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise NativeAPIError(409, "workspace_unavailable", "The configured workspace is unavailable.") from None
    if not root.is_dir():
        raise NativeAPIError(409, "workspace_unavailable", "The configured workspace is unavailable.")
    return root


def _relative(root: Path, raw_path: str | None) -> tuple[str, ...]:
    if raw_path is None:
        return ()
    if not raw_path or len(raw_path.encode("utf-8")) > 4_096 or any(ord(character) < 32 for character in raw_path):
        raise NativeAPIError(422, "invalid_path", "The workspace path is invalid.")
    try:
        candidate = Path(raw_path)
    except (OSError, RuntimeError, ValueError):
        raise NativeAPIError(422, "invalid_path", "The workspace path is invalid.") from None
    if not candidate.is_absolute():
        raise NativeAPIError(422, "invalid_path", "The workspace path must be absolute.")
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        raise NativeAPIError(403, "path_outside_workspace", "The requested path is outside the configured workspace.") from None
    parts = relative.parts
    if any(part in {"", ".", ".."} or os.sep in part or (os.altsep and os.altsep in part) for part in parts):
        raise NativeAPIError(422, "invalid_path", "The workspace path is invalid.")
    return parts


def _response_path(root: Path, parts: tuple[str, ...]) -> str:
    return str(root.joinpath(*parts))


@contextmanager
def _opened_posix(root: Path, parts: tuple[str, ...], *, directory: bool) -> Iterator[int]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise NativeAPIError(501, "secure_traversal_unavailable", "Secure workspace traversal is unavailable on this host.")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        try:
            descriptors.append(os.open(root, directory_flags))
            for component in parts[:-1] if not directory else parts:
                descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
            if directory:
                yield descriptors[-1]
            else:
                if not parts:
                    raise NativeAPIError(422, "invalid_path", "A regular workspace file is required.")
                file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                descriptors.append(os.open(parts[-1], file_flags, dir_fd=descriptors[-1]))
                yield descriptors[-1]
        except FileNotFoundError:
            raise NativeAPIError(404, "file_not_found", "The workspace path no longer exists.") from None
        except NotADirectoryError:
            raise NativeAPIError(422, "invalid_path", "The workspace path is not a directory.") from None
        except OSError:
            raise NativeAPIError(409, "unsafe_workspace_path", "The workspace path cannot be traversed safely.") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _opened(root: Path, parts: tuple[str, ...], *, directory: bool) -> Iterator[int | Path]:
    if os.name != "nt":
        with _opened_posix(root, parts, directory=directory) as descriptor:
            yield descriptor
        return
    # A resolve-then-open fallback can race junction or symlink replacement.
    # Do not advertise confined access without a handle-relative implementation.
    raise NativeAPIError(501, "secure_traversal_unavailable", "Secure workspace traversal is unavailable on this host.")


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_nsec", ctypes.c_uint32), ("reserved", ctypes.c_int32)]


class _Statx(ctypes.Structure):
    _fields_ = [
        ("mask", ctypes.c_uint32), ("blksize", ctypes.c_uint32), ("attributes", ctypes.c_uint64),
        ("nlink", ctypes.c_uint32), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16), ("spare0", ctypes.c_uint16), ("ino", ctypes.c_uint64),
        ("size", ctypes.c_uint64), ("blocks", ctypes.c_uint64), ("attributes_mask", ctypes.c_uint64),
        ("atime", _StatxTimestamp), ("btime", _StatxTimestamp), ("ctime", _StatxTimestamp),
        ("mtime", _StatxTimestamp), ("rdev_major", ctypes.c_uint32), ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32), ("dev_minor", ctypes.c_uint32), ("mnt_id", ctypes.c_uint64),
        ("dio_mem_align", ctypes.c_uint32), ("dio_offset_align", ctypes.c_uint32),
        ("spare3", ctypes.c_uint64 * 12),
    ]


def _linux_birthtime(descriptor: int) -> float | None:
    if not sys_platform_linux():
        return None
    try:
        function = ctypes.CDLL(None, use_errno=True).statx
    except (AttributeError, OSError):
        return None
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(_Statx)]
    function.restype = ctypes.c_int
    result = _Statx()
    # AT_EMPTY_PATH asks statx to inspect the already confined descriptor.
    if function(descriptor, b"", 0x1000 | 0x100, 0x0800, ctypes.byref(result)) != 0 or not result.mask & 0x0800:
        return None
    value = float(result.btime.tv_sec) + float(result.btime.tv_nsec) / 1_000_000_000
    return value if math.isfinite(value) and value > 0 else None


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux")


def _birthtime(info: os.stat_result, descriptor: int | None = None) -> float | None:
    value = getattr(info, "st_birthtime", None)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
        if math.isfinite(result) and result > 0:
            return result
    if descriptor is not None:
        return _linux_birthtime(descriptor)
    return None


def _entry(root: Path, parent_parts: tuple[str, ...], name: str, info: os.stat_result, descriptor: int | None = None) -> dict[str, Any] | None:
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        return None
    is_directory = stat.S_ISDIR(info.st_mode)
    return {
        "name": name,
        "path": _response_path(root, parent_parts + (name,)),
        "is_directory": is_directory,
        "size": None if is_directory else info.st_size,
        "created": _birthtime(info, descriptor),
        "mtime": info.st_mtime,
        "mime_type": None if is_directory else (mimetypes.guess_type(name)[0] or "application/octet-stream"),
    }


def _list(root: Path, parts: tuple[str, ...], profile_id: str) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    with _opened(root, parts, directory=True) as opened:
        try:
            names = sorted(os.listdir(opened))
        except OSError:
            raise NativeAPIError(409, "workspace_unreadable", "The workspace directory could not be read safely.") from None
        if len(names) > MAX_ROWS:
            raise NativeAPIError(413, "directory_too_large", "The workspace directory exceeds the row limit.")
        for name in names:
            if not isinstance(name, str) or name in {"", ".", ".."} or os.sep in name or (os.altsep and os.altsep in name):
                continue
            try:
                if isinstance(opened, int):
                    info = os.stat(name, dir_fd=opened, follow_symlinks=False)
                    child_fd = None
                    if stat.S_ISREG(info.st_mode):
                        try:
                            file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                            child_fd = os.open(name, file_flags, dir_fd=opened)
                            info = os.fstat(child_fd)
                        except OSError:
                            if child_fd is not None:
                                os.close(child_fd)
                            continue
                    projected = _entry(root, parts, name, info, child_fd)
                    if child_fd is not None:
                        os.close(child_fd)
                else:
                    child = opened / name
                    info = child.lstat()
                    projected = _entry(root, parts, name, info)
            except OSError:
                continue
            if projected is not None:
                entries.append(projected)
    path = _response_path(root, parts)
    parent = None if not parts else _response_path(root, parts[:-1])
    return {
        "workspace": {"root": str(root), "source": "terminal.cwd", "profileId": profile_id},
        "path": path, "parent": parent, "entries": entries,
        "root": str(root), "locked_root": str(root), "can_change_path": False,
    }


def _scope(root: Path, profile_id: str) -> dict[str, Any]:
    return {
        "workspace": {"root": str(root), "source": "terminal.cwd", "profileId": profile_id},
        "path": str(root), "parent": None, "entries": [],
        "root": str(root), "locked_root": str(root), "can_change_path": False,
    }


def _skip_recent_directory(name: str) -> bool:
    return name in _RECENT_SKIPPED_NAMES or name.endswith(_RECENT_SKIPPED_SUFFIXES)


def _skip_recent_file(name: str) -> bool:
    return name.startswith(".") or name.endswith(_RECENT_SKIPPED_EXTENSIONS)


def _agent_written_paths(profile_id: str) -> list[tuple[float, str]]:
    """Absolute paths the agent wrote, patched or delivered, newest first."""
    import re
    import sqlite3
    from hermes_cli.profiles import get_profile_dir
    database = get_profile_dir(profile_id) / "state.db"
    if not database.is_file():
        return []
    marks = " OR ".join("instr(tool_calls, ?) > 0" for _ in _WRITING_TOOLS)
    try:
        with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5) as connection:
            calls = connection.execute(
                f"SELECT timestamp, tool_calls FROM messages WHERE role = 'assistant' "
                f"AND tool_calls IS NOT NULL AND ({marks}) ORDER BY timestamp DESC LIMIT ?",
                (*(f'"{name}"' for name in _WRITING_TOOLS), RECENT_HISTORY_ROWS),
            ).fetchall()
            deliveries = connection.execute(
                "SELECT timestamp, content FROM messages WHERE role = 'assistant' "
                "AND instr(content, 'MEDIA:') > 0 ORDER BY timestamp DESC LIMIT ?",
                (RECENT_HISTORY_ROWS,),
            ).fetchall()
    except sqlite3.Error:
        return []
    found: list[tuple[float, str]] = []
    for timestamp, raw in calls:
        try:
            values = json.loads(raw or "[]")
        except ValueError:
            continue
        for call in values if isinstance(values, list) else []:
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict) or function.get("name") not in _WRITING_TOOLS:
                continue
            try:
                arguments = function.get("arguments")
                arguments = json.loads(arguments) if isinstance(arguments, str) else arguments
            except ValueError:
                continue
            path = arguments.get("path") if isinstance(arguments, dict) else None
            if isinstance(path, str):
                found.append((float(timestamp), path))
    directive = re.compile(r"MEDIA:(?://)?(/[^\n`]+)")
    for timestamp, content in deliveries:
        for match in directive.finditer(content or ""):
            found.append((float(timestamp), "/" + match.group(1).strip().lstrip("/")))
    found.sort(key=lambda row: row[0], reverse=True)
    return found


def _confined_entry(root: Path, raw_path: str) -> tuple[tuple[str, ...], dict[str, Any]] | None:
    """A workspace entry for an absolute path that still resolves inside the root."""
    try:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            return None
        resolved = candidate.resolve(strict=True)
        parts = resolved.relative_to(root).parts
    except (OSError, RuntimeError, ValueError):
        return None
    if not parts or any(part.startswith(".") for part in parts) or _skip_recent_file(parts[-1]):
        return None
    try:
        with _opened(root, parts, directory=False) as descriptor:
            info = os.fstat(descriptor) if isinstance(descriptor, int) else descriptor.stat()
            projected = _entry(root, parts[:-1], parts[-1], info,
                               descriptor if isinstance(descriptor, int) else None)
    except NativeAPIError:
        return None
    if projected is None or projected["is_directory"]:
        return None
    return parts, projected


def _shallow_newest(root: Path, deadline: float) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    """Files in the top folders, opened O_NOFOLLOW relative to their parent."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    found: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    directories = 0

    def visit(descriptor: int, parts: tuple[str, ...]) -> None:
        nonlocal directories
        directories += 1
        folders: list[str] = []
        files: list[tuple[tuple[str, ...], dict[str, Any]]] = []
        is_repository = False
        try:
            with os.scandir(descriptor) as iterator:
                for item in iterator:
                    name = item.name
                    if name == ".git":
                        is_repository = True
                    if not name or name.startswith(".") or os.sep in name or (os.altsep and os.altsep in name):
                        continue
                    try:
                        info = item.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if not _skip_recent_directory(name):
                            folders.append(name)
                    elif not _skip_recent_file(name):
                        projected = _entry(root, parts, name, info)
                        if projected is not None and not projected["is_directory"]:
                            files.append((parts + (name,), projected))
        except OSError:
            return
        # A code repository's files are new whenever it is cloned. What the
        # agent writes there still arrives through its own history above.
        if is_repository and parts:
            return
        found.extend(files)
        if len(parts) + 1 > RECENT_SHALLOW_DEPTH:
            return
        for name in sorted(folders):
            if directories >= RECENT_SHALLOW_DIRECTORIES or time.monotonic() > deadline:
                return
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except OSError:
                continue
            try:
                visit(child, parts + (name,))
            finally:
                os.close(child)

    try:
        top = os.open(root, flags)
    except OSError:
        raise NativeAPIError(409, "workspace_unreadable", "The workspace directory could not be read safely.") from None
    try:
        visit(top, ())
    finally:
        os.close(top)
    return found


def _recent(root: Path, profile_id: str) -> dict[str, Any]:
    """Artifacts: files the agent wrote or delivered, plus new top-level files.

    Agent files rank by when the agent wrote them; others by creation time.
    Every entry is re-opened O_NOFOLLOW below the root, so history can never
    point the app outside the configured workspace.
    """
    deadline = time.monotonic() + RECENT_SHALLOW_SECONDS
    ranked: dict[tuple[str, ...], tuple[float, dict[str, Any]]] = {}
    for timestamp, raw_path in _agent_written_paths(profile_id):
        if len(ranked) >= RECENT_LIMIT:
            break
        confined = _confined_entry(root, raw_path)
        if confined is not None and confined[0] not in ranked:
            ranked[confined[0]] = (timestamp, confined[1])
    for parts, projected in _shallow_newest(root, deadline):
        if parts not in ranked:
            ranked[parts] = (projected["created"] or projected["mtime"], projected)
    newest = heapq.nlargest(RECENT_LIMIT, ranked.values(), key=lambda row: row[0])
    entries = [row[1] for row in newest]
    result = {
        "workspace": {"root": str(root), "source": "terminal.cwd", "profileId": profile_id},
        "path": str(root), "parent": None, "entries": entries,
        "root": str(root), "locked_root": str(root), "can_change_path": False,
    }
    # Long paths can outgrow the listing budget; keep the newest that fit.
    while entries and len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) > MAX_LISTING_BYTES - 1_024:
        entries.pop()
    return result


def _read(root: Path, parts: tuple[str, ...], profile_id: str) -> dict[str, Any]:
    with _opened(root, parts, directory=False) as opened:
        try:
            if isinstance(opened, int):
                info = os.fstat(opened)
                if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_FILE_BYTES:
                    raise NativeAPIError(413, "file_too_large", "The workspace file is empty or exceeds the native preview limit.")
                chunks: list[bytes] = []
                remaining = info.st_size
                while remaining:
                    chunk = os.read(opened, min(remaining, 64 * 1_024))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
            else:
                info = opened.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_FILE_BYTES:
                    raise NativeAPIError(413, "file_too_large", "The workspace file is empty or exceeds the native preview limit.")
                content = opened.read_bytes()
        except NativeAPIError:
            raise
        except OSError:
            raise NativeAPIError(409, "workspace_unreadable", "The workspace file could not be read safely.") from None
    if len(content) != info.st_size or len(content) > MAX_FILE_BYTES:
        raise NativeAPIError(409, "file_changed", "The workspace file changed while it was being read.")
    path = _response_path(root, parts)
    name = parts[-1]
    mime_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
    return {
        "workspace": {"root": str(root), "source": "terminal.cwd", "profileId": profile_id},
        "path": path, "size": len(content), "mime_type": mime_type,
        "data_url": "data:" + mime_type + ";base64," + base64.b64encode(content).decode("ascii"),
        "root": str(root), "locked_root": str(root), "can_change_path": False,
    }


async def request(operation: str, request: Request) -> Response:
    context = native_context(request)
    request_id = _precondition(request, context)
    body = await _body(request)
    if native_context(request) != context:
        raise NativeAPIError(412, "context_changed", "The native context changed; refresh before retrying.")
    root = _configured_root(context.serving_profile_id)
    profile_id = context.serving_profile_id
    if profile_id is None:
        raise NativeAPIError(501, "workspace_identity_unavailable", "This host cannot identify its serving profile workspace.")
    if operation == "scope":
        if body.path is not None:
            raise NativeAPIError(422, "invalid_request", "Workspace scope discovery does not accept a path.")
        result = _scope(root, profile_id)
        maximum = MAX_LISTING_BYTES
    elif operation == "list":
        parts = _relative(root, body.path)
        result = await run_in_threadpool(_list, root, parts, profile_id)
        maximum = MAX_LISTING_BYTES
    elif operation == "read":
        parts = _relative(root, body.path)
        result = await run_in_threadpool(_read, root, parts, profile_id)
        maximum = MAX_READ_RESPONSE_BYTES
    elif operation == "recent":
        if body.path is not None:
            raise NativeAPIError(422, "invalid_request", "Recent workspace files do not accept a path.")
        result = await run_in_threadpool(_recent, root, profile_id)
        maximum = MAX_LISTING_BYTES
    else:
        raise NativeAPIError(404, "unsupported_operation", "The workspace file operation is unsupported.")
    if native_context(request) != context:
        raise NativeAPIError(412, "context_changed", "The native context changed; retry against the current workspace.")
    if _configured_root(profile_id) != root:
        raise NativeAPIError(409, "workspace_changed", "The configured workspace changed; refresh before retrying.")
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
    if len(encoded) > maximum:
        raise NativeAPIError(413, "payload_too_large", "The workspace file response exceeds the byte limit.")
    return Response(encoded, media_type="application/json", headers={
        "Cache-Control": "no-store", "ETag": context.etag, "X-Loopdy-Request-ID": request_id,
    })


async def _body(request: Request) -> _Body:
    if request.query_params or request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise NativeAPIError(422, "invalid_request", "A JSON workspace file request is required.")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > MAX_BODY_BYTES:
            raise NativeAPIError(413, "payload_too_large", "The workspace file request exceeds the byte limit.")
        content.extend(chunk)
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_invalid_number,
        )
        return _Body.model_validate(value)
    except (ValueError, UnicodeError, TypeError):
        raise NativeAPIError(422, "invalid_request", "The workspace file request is invalid.") from None


def _precondition(request: Request, context: NativeContext) -> str:
    from .native_api import _REQUEST_ID
    if len(request.headers.getlist("if-match")) != 1 or request.headers.get("if-match") != context.etag:
        raise NativeAPIError(412 if request.headers.get("if-match") is not None else 428, "context_changed" if request.headers.get("if-match") is not None else "context_required", "Load the current native context before this request.")
    request_id = request.headers.get("x-loopdy-request-id", "")
    if len(request.headers.getlist("x-loopdy-request-id")) != 1 or _REQUEST_ID.fullmatch(request_id) is None:
        raise NativeAPIError(422, "invalid_request", "A canonical request ID is required.")
    return request_id
