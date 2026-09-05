"""Durable, restart-safe self-update coordination for the Loopdy plugin.

The journal and copied worker live in profile-local plugin data, outside the
replaceable installation.  This module never accepts an update source, ref,
path, command, or executable from a client.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


SOURCE_URL = "https://github.com/promptclickrun/loopdy-plugin"
SOURCE_BRANCH = "main"
PLUGIN_NAME = "loopdy"
_OPERATION_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_PROFILE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_TERMINAL_PHASES = frozenset(
    {"complete", "up_to_date", "installed_restart_required", "blocked", "failed"}
)
_PUBLIC_FIELDS = (
    "operation_id",
    "phase",
    "target_revision",
    "installed_revision",
    "active_revision",
    "runtime_id",
    "message",
)
_PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def _hermes_home_for_plugin(plugin_root: Path) -> Path:
    resolved = plugin_root.resolve()
    if resolved.parent.name == "plugins" and resolved.name == PLUGIN_NAME:
        return resolved.parent.parent
    configured = os.getenv("HERMES_HOME")
    return Path(configured).expanduser().resolve() if configured else Path.home() / ".hermes"


def _metadata_revision(plugin_root: Path) -> str:
    home = _hermes_home_for_plugin(plugin_root)
    metadata_path = home / "plugins" / ".install-metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        entry = metadata.get(PLUGIN_NAME) if isinstance(metadata, dict) else None
        revision = str(entry.get("revision") or "").lower() if isinstance(entry, dict) else ""
        if _REVISION.fullmatch(revision):
            return revision
    except (OSError, ValueError, TypeError):
        pass
    # A directly cloned standalone plugin can identify itself without metadata.
    if (plugin_root / ".git").is_dir():
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(plugin_root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
            revision = result.stdout.strip().lower()
            if result.returncode == 0 and _REVISION.fullmatch(revision):
                return revision
        except (OSError, subprocess.TimeoutExpired):
            pass
    return ""


# These values are intentionally fixed at module import. Reading newly installed
# files from an old gateway process must never masquerade as activation.
LOADED_REVISION = _metadata_revision(_PLUGIN_ROOT)
RUNTIME_ID = "runtime_" + secrets.token_urlsafe(18).replace("-", "_")


class PluginUpdateError(RuntimeError):
    """A bounded updater failure suitable for conversion to a public status."""


class _FileLock:
    def __init__(self, path: Path, *, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout
        self.handle: Any | None = None

    def __enter__(self) -> "_FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle = self.path.open("a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":  # pragma: no cover - updater launch is fail-closed on Windows
                    import msvcrt

                    if handle.seek(0, os.SEEK_END) == 0:
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.handle = handle
                return self
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    handle.close()
                    raise
                if time.monotonic() >= deadline:
                    handle.close()
                    raise TimeoutError("Loopdy plugin update state is busy") from exc
                time.sleep(0.05)

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        handle, self.handle = self.handle, None
        if handle is None:
            return
        try:
            if os.name == "nt":  # pragma: no cover
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


class PluginUpdateManager:
    """Own one profile-local update journal and its authenticated operations."""

    def __init__(
        self,
        data_root: Path,
        plugin_root: Path,
        profile: str,
        launch_worker: Callable[[str], Any] | None = None,
    ) -> None:
        self.data_root = Path(data_root).expanduser().resolve()
        self.plugin_root = Path(plugin_root).expanduser().resolve()
        self.profile = _profile(profile)
        self.hermes_home = _hermes_home_for_plugin(self.plugin_root).resolve()
        self.journal_path = self.data_root / "journal.json"
        self.state_lock_path = self.data_root / "journal.lock"
        self.install_lock_path = self.data_root / "installation.lock"
        self._launch_worker = launch_worker or self._launch_detached_worker
        self.data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.data_root.chmod(0o700)
        except OSError:
            pass

    def start(self, operation_id: str, device_id: str, restart: bool) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        device_id = _device_id(device_id)
        if type(restart) is not bool:
            raise ValueError("Loopdy plugin update restart choice is invalid")

        with _FileLock(self.state_lock_path):
            state = self._read_state()
            existing = state["operations"].get(operation_id)
            if existing is not None:
                if (
                    existing.get("device_id") != device_id
                    or existing.get("restart") is not restart
                    or existing.get("profile") != self.profile
                    or existing.get("plugin_root") != str(self.plugin_root)
                ):
                    raise ValueError("Loopdy plugin update operation conflicts with existing state")
                return self._public_status(state, existing)

            for operation in state["operations"].values():
                if operation.get("phase") not in _TERMINAL_PHASES:
                    raise ValueError("Another Loopdy plugin update is already in progress")

            runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
            now = int(time.time())
            operation = {
                "operation_id": operation_id,
                "device_id": device_id,
                "restart": restart,
                "profile": self.profile,
                "plugin_root": str(self.plugin_root),
                "phase": "launching",
                "message": "Preparing the Loopdy plugin update.",
                "target_revision": "",
                "prior_revision": _metadata_revision(self.plugin_root),
                "started_runtime_id": str(runtime.get("runtime_id") or ""),
                "created_at": now,
                "updated_at": now,
                "worker_launch_recorded": True,
                "restart_requested_at": 0,
                "link_response_runtime_id": "",
            }
            state["operations"][operation_id] = operation
            state["latest_operation_id"] = operation_id
            self._trim_operations(state)
            # Persist ownership and launch intent before starting anything.
            self._write_state(state)

        try:
            self._launch_worker(operation_id)
        except Exception:
            with _FileLock(self.state_lock_path):
                state = self._read_state()
                current = state["operations"].get(operation_id)
                if isinstance(current, dict) and current.get("phase") == "launching":
                    current["phase"] = "blocked"
                    current["message"] = (
                        "This host cannot launch a restart-safe updater. Run the update from a supported service-managed host."
                    )
                    current["updated_at"] = int(time.time())
                    self._write_state(state)
                return self._public_status(state, current if isinstance(current, dict) else None)
        return self.status(operation_id=operation_id, device_id=device_id)

    def status(
        self,
        operation_id: str | None = None,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        if operation_id is not None:
            operation_id = _operation_id(operation_id)
        if device_id is not None:
            device_id = _device_id(device_id)
        with _FileLock(self.state_lock_path):
            state = self._read_state()
            selected = operation_id or str(state.get("latest_operation_id") or "")
            operation = state["operations"].get(selected) if selected else None
            if operation is None:
                if operation_id is not None:
                    raise ValueError("Loopdy plugin update operation was not found")
                return self._idle_status(state)
            if device_id is not None and operation.get("device_id") not in {device_id, local_cli_device_id(self.profile)}:
                raise ValueError("Loopdy plugin update operation belongs to another device")
            if self._reconcile_completion(state, operation):
                self._write_state(state)
            return self._public_status(state, operation)

    def record_runtime_loaded(self) -> None:
        """Record the import-time revision/nonce from a true gateway lifecycle."""
        with _FileLock(self.state_lock_path):
            state = self._read_state()
            state["runtime"] = {
                "revision": LOADED_REVISION,
                "runtime_id": RUNTIME_ID,
                "pid": os.getpid(),
                "observed_at": int(time.time()),
            }
            self._write_state(state)

    def record_link_response(
        self, device_id: str, operation_id: str | None = None
    ) -> None:
        """Bind an authenticated update response to this loaded runtime."""
        device_id = _device_id(device_id)
        if operation_id is not None:
            operation_id = _operation_id(operation_id)
        with _FileLock(self.state_lock_path):
            state = self._read_state()
            selected = operation_id or str(state.get("latest_operation_id") or "")
            operation = state["operations"].get(selected) if selected else None
            if operation is None or operation.get("device_id") not in {device_id, local_cli_device_id(self.profile)}:
                return
            runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
            if runtime.get("runtime_id") == RUNTIME_ID and runtime.get("revision") == LOADED_REVISION:
                operation["link_response_runtime_id"] = RUNTIME_ID
                operation["updated_at"] = int(time.time())
                self._reconcile_completion(state, operation)
                self._write_state(state)

    # Worker-facing journal methods. They remain private to the copied worker.
    def _worker_operation(self, operation_id: str) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        with _FileLock(self.state_lock_path):
            state = self._read_state()
            operation = state["operations"].get(operation_id)
            if not isinstance(operation, dict):
                raise PluginUpdateError("Update operation is unavailable")
            return dict(operation)

    def _worker_transition(
        self,
        operation_id: str,
        phase: str,
        message: str,
        **fields: Any,
    ) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        if not isinstance(phase, str) or not 1 <= len(phase) <= 64:
            raise PluginUpdateError("Update phase is invalid")
        message = _bounded_message(message)
        with _FileLock(self.state_lock_path):
            state = self._read_state()
            operation = state["operations"].get(operation_id)
            if not isinstance(operation, dict):
                raise PluginUpdateError("Update operation is unavailable")
            if operation.get("phase") in _TERMINAL_PHASES:
                return dict(operation)
            operation["phase"] = phase
            operation["message"] = message
            operation["updated_at"] = int(time.time())
            allowed = {
                "target_revision",
                "prior_revision",
                "backup_path",
                "restart_requested_at",
            }
            for key, value in fields.items():
                if key in allowed:
                    operation[key] = value
            self._write_state(state)
            return dict(operation)

    def _read_state(self) -> dict[str, Any]:
        if not self.journal_path.exists():
            return {"version": 1, "latest_operation_id": "", "operations": {}}
        try:
            value = json.loads(self.journal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PluginUpdateError("Loopdy plugin update journal is unreadable") from exc
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or not isinstance(value.get("operations"), dict)
        ):
            raise PluginUpdateError("Loopdy plugin update journal is invalid")
        operations = value["operations"]
        if len(operations) > 64:
            raise PluginUpdateError("Loopdy plugin update journal is invalid")
        for key, operation in operations.items():
            if (
                not isinstance(key, str)
                or _OPERATION_ID.fullmatch(key) is None
                or not isinstance(operation, dict)
                or operation.get("operation_id") != key
            ):
                raise PluginUpdateError("Loopdy plugin update journal is invalid")
        latest = value.get("latest_operation_id", "")
        if latest and (not isinstance(latest, str) or latest not in operations):
            raise PluginUpdateError("Loopdy plugin update journal is invalid")
        runtime = value.get("runtime")
        if runtime is not None and not isinstance(runtime, dict):
            raise PluginUpdateError("Loopdy plugin update journal is invalid")
        return value

    def _write_state(self, state: dict[str, Any]) -> None:
        self.data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = json.dumps(state, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
        fd, temporary = tempfile.mkstemp(prefix="journal.", suffix=".tmp", dir=self.data_root)
        path = Path(temporary)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(path, self.journal_path)
            try:
                self.journal_path.chmod(0o600)
            except OSError:
                pass
        finally:
            path.unlink(missing_ok=True)

    def _public_status(
        self, state: dict[str, Any], operation: dict[str, Any] | None
    ) -> dict[str, Any]:
        if not isinstance(operation, dict):
            return self._idle_status(state)
        runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
        active_revision = str(runtime.get("revision") or "")
        runtime_id = str(runtime.get("runtime_id") or "")
        value = {
            "operation_id": str(operation.get("operation_id") or ""),
            "phase": str(operation.get("phase") or "failed")[:64],
            "target_revision": str(operation.get("target_revision") or "")[:40],
            "installed_revision": _metadata_revision(self.plugin_root),
            "active_revision": active_revision[:40],
            "runtime_id": runtime_id[:128],
            "message": _bounded_message(operation.get("message") or "Update status is unavailable."),
        }
        return _wire_status(value)

    def _idle_status(self, state: dict[str, Any]) -> dict[str, Any]:
        runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
        installed = _metadata_revision(self.plugin_root)
        value = {
            "operation_id": "",
            "phase": "idle",
            "target_revision": "",
            "installed_revision": installed,
            "active_revision": str(runtime.get("revision") or "")[:40],
            "runtime_id": str(runtime.get("runtime_id") or "")[:128],
            "message": "No Loopdy plugin update is in progress.",
        }
        return _wire_status(value)

    def _reconcile_completion(self, state: dict[str, Any], operation: dict[str, Any]) -> bool:
        if operation.get("phase") not in {
            "awaiting_activation",
            "reconnecting",
            "restart_requested",
            "timed_out",
        }:
            return False
        target = str(operation.get("target_revision") or "")
        runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
        runtime_id = str(runtime.get("runtime_id") or "")
        fresh = bool(runtime_id and runtime_id != operation.get("started_runtime_id"))
        if (
            _REVISION.fullmatch(target)
            and runtime.get("revision") == target
            and fresh
            and operation.get("link_response_runtime_id") == runtime_id
        ):
            operation["phase"] = "complete"
            operation["message"] = "The updated Loopdy plugin is active and Link responded."
            operation["updated_at"] = int(time.time())
            return True
        return False

    def _trim_operations(self, state: dict[str, Any]) -> None:
        operations = state["operations"]
        if len(operations) <= 32:
            return
        ordered = sorted(
            operations.items(), key=lambda item: int(item[1].get("created_at") or 0)
        )
        for key, operation in ordered:
            if len(operations) <= 32:
                break
            if operation.get("phase") in _TERMINAL_PHASES:
                operations.pop(key, None)

    def _launch_detached_worker(self, operation_id: str) -> None:
        expected = self.hermes_home / "plugins" / PLUGIN_NAME
        if self.plugin_root != expected:
            raise PluginUpdateError("Self-update requires an installed Loopdy plugin")

        worker_root = self.data_root / "workers" / operation_id
        worker_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        source_root = Path(__file__).resolve().parent
        for name in ("plugin_update.py", "plugin_update_worker.py"):
            destination = worker_root / name
            shutil.copy2(source_root / name, destination)
            destination.chmod(0o700 if name.endswith("worker.py") else 0o600)

        worker = worker_root / "plugin_update_worker.py"
        command = [
            sys.executable,
            str(worker),
            "--data-root",
            str(self.data_root),
            "--plugin-root",
            str(self.plugin_root),
            "--profile",
            self.profile,
            "--operation-id",
            operation_id,
        ]
        clean_command = _clean_exec_command(command, hermes_home=self.hermes_home)
        system = platform.system()
        digest = hashlib.sha256(operation_id.encode("ascii")).hexdigest()[:20]
        if system == "Darwin":
            launchctl = shutil.which("launchctl")
            if not launchctl:
                raise PluginUpdateError("launchctl is unavailable")
            label = f"app.loopdy.plugin-update.{os.getuid()}.{digest}"
            full_command = [
                launchctl,
                "submit",
                "-l",
                label,
                "-o",
                "/dev/null",
                "-e",
                "/dev/null",
                "--",
                *clean_command,
                "--service-label",
                label,
            ]
        elif system == "Linux":
            systemd_run = shutil.which("systemd-run")
            if not systemd_run:
                raise PluginUpdateError("systemd-run is unavailable")
            full_command = [
                systemd_run,
                "--user",
                f"--unit=loopdy-plugin-update-{digest}",
                "--collect",
                "--no-block",
                "--service-type=exec",
                "--",
                *clean_command,
            ]
        else:
            raise PluginUpdateError("Restart-safe plugin update is unsupported on this platform")

        result = subprocess.run(
            full_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            env=_launcher_env(),
        )
        if result.returncode != 0:
            raise PluginUpdateError("The service manager rejected the updater job")


def _clean_exec_command(command: list[str], *, hermes_home: Path) -> list[str]:
    env_tool = shutil.which("env") or "/usr/bin/env"
    path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    home = str(Path.home())
    return [
        env_tool,
        "-i",
        f"PATH={path}",
        f"HOME={home}",
        f"HERMES_HOME={hermes_home}",
        "LANG=C.UTF-8",
        "PYTHONUTF8=1",
        *command,
    ]


def _launcher_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
    }


def _wire_status(value: dict[str, Any]) -> dict[str, Any]:
    phases = {
        "launching": "accepted", "resolved": "resolving",
        "validating_installation": "validating", "staging": "validating", "backing_up": "validating",
        "installed": "installing", "restart_requested": "restarting",
        "awaiting_activation": "waiting_for_activation", "reconnecting": "waiting_for_activation",
    }
    result = {key: value[key] for key in _PUBLIC_FIELDS}
    result["phase"] = phases.get(result["phase"], result["phase"])
    for key in ("operation_id", "target_revision", "installed_revision", "active_revision", "runtime_id"):
        result[key] = result[key] or None
    return result


def _operation_id(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION_ID.fullmatch(value) is None:
        raise ValueError("Loopdy plugin update operation ID is invalid")
    return value


def _device_id(value: Any) -> str:
    if not isinstance(value, str) or _DEVICE_ID.fullmatch(value) is None:
        raise ValueError("Loopdy plugin update device ID is invalid")
    return value


def _profile(value: Any) -> str:
    if not isinstance(value, str) or _PROFILE.fullmatch(value) is None:
        raise ValueError("Loopdy plugin update profile is invalid")
    return value


def _bounded_message(value: Any) -> str:
    message = " ".join(str(value).split())
    if not message:
        message = "Update status is unavailable."
    return message[:240]


def new_operation_id() -> str:
    return "update_" + secrets.token_urlsafe(24).replace("-", "_")


def local_cli_device_id(profile: str) -> str:
    profile = _profile(profile)
    digest = hashlib.sha256(profile.encode("utf-8")).hexdigest()[:24]
    return f"local_cli_{digest}"


def production_manager(profile: str, *, launch_worker: Callable[[str], Any] | None = None) -> PluginUpdateManager:
    """Build the only production path: profile data plus installed plugin bytes."""
    try:
        from hermes_constants import get_hermes_home

        home = Path(get_hermes_home()).resolve()
    except Exception:
        home = _hermes_home_for_plugin(_PLUGIN_ROOT).resolve()
    manager = PluginUpdateManager(
        data_root=home / "plugin-data" / PLUGIN_NAME / "plugin-update",
        plugin_root=_PLUGIN_ROOT,
        profile=profile,
        launch_worker=launch_worker,
    )
    # Current profile authority must not be inferred from an inherited plugin path.
    manager.hermes_home = home
    return manager


__all__ = [
    "LOADED_REVISION",
    "PLUGIN_NAME",
    "PluginUpdateError",
    "PluginUpdateManager",
    "RUNTIME_ID",
    "SOURCE_BRANCH",
    "SOURCE_URL",
    "local_cli_device_id",
    "new_operation_id",
    "production_manager",
]
