"""Independent one-shot worker for Loopdy plugin self-update operations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from plugin_update import (
    PLUGIN_NAME,
    SOURCE_BRANCH,
    SOURCE_URL,
    PluginUpdateError,
    PluginUpdateManager,
    _FileLock,
    _metadata_revision,
)


_REVISION = re.compile(r"^[0-9a-f]{40}$")
_MAX_CAPTURE = 4096
_ACTIVATION_WAIT_SECONDS = 300


class UpdateBlocked(PluginUpdateError):
    pass


class UpdateFailed(PluginUpdateError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--plugin-root", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--service-label", default="")
    args = parser.parse_args(argv)

    manager = PluginUpdateManager(
        data_root=Path(args.data_root),
        plugin_root=Path(args.plugin_root),
        profile=args.profile,
        # This process executes an existing operation and must never launch one.
        launch_worker=lambda _operation_id: None,
    )
    try:
        with _FileLock(manager.install_lock_path, timeout=2.0):
            _run_operation(manager, args.operation_id)
    except TimeoutError:
        _transition_if_possible(
            manager,
            args.operation_id,
            "blocked",
            "Another process owns the Loopdy plugin installation lock.",
        )
    except UpdateBlocked:
        _transition_if_possible(
            manager,
            args.operation_id,
            "blocked",
            "The Loopdy plugin update was blocked before installation. Review the host with Plugin Doctor.",
        )
    except Exception:
        _transition_if_possible(
            manager,
            args.operation_id,
            "failed",
            "The Loopdy plugin update failed. The previous installation remains available for recovery.",
        )
    finally:
        if args.service_label and sys.platform == "darwin":
            _remove_launchd_job(args.service_label)
    return 0


def _run_operation(manager: PluginUpdateManager, operation_id: str) -> None:
    operation = manager._worker_operation(operation_id)
    if operation.get("phase") in {
        "complete",
        "up_to_date",
        "installed_restart_required",
        "blocked",
        "failed",
    }:
        return
    if operation.get("profile") != manager.profile:
        raise UpdateBlocked("Profile ownership mismatch")
    if Path(str(operation.get("plugin_root") or "")).resolve() != manager.plugin_root:
        raise UpdateBlocked("Plugin path ownership mismatch")
    expected_plugin_root = (manager.hermes_home / "plugins" / PLUGIN_NAME).resolve()
    if manager.plugin_root != expected_plugin_root:
        raise UpdateBlocked("Plugin is not installed in the active profile")

    target = str(operation.get("target_revision") or "")
    if not _REVISION.fullmatch(target):
        manager._worker_transition(
            operation_id,
            "resolving",
            "Resolving the fixed Loopdy plugin source to an immutable revision.",
        )
        target = _resolve_target_revision(manager.hermes_home)
        manager._worker_transition(
            operation_id,
            "resolved",
            "Resolved the Loopdy plugin update revision.",
            target_revision=target,
        )
        operation = manager._worker_operation(operation_id)

    installed = _metadata_revision(manager.plugin_root)
    prior_revision, prior_source, prior_subdir = _recognized_installation(manager)
    _verify_installed_tree(manager, revision=prior_revision, source_url=prior_source, subdir=prior_subdir)
    active = manager.status(operation_id=operation_id).get("active_revision", "")
    if installed == target and active == target:
        manager._worker_transition(
            operation_id,
            "up_to_date",
            "The installed and active Loopdy plugin already match the latest revision.",
        )
        return

    if installed != target:
        manager._worker_transition(
            operation_id,
            "validating_installation",
            "Validating the current Loopdy plugin installation.",
        )

        staging_root = manager.data_root / "staging"
        staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix=f"{operation_id}.", dir=staging_root) as directory:
            staged_repo = Path(directory) / "repo"
            manager._worker_transition(
                operation_id,
                "staging",
                "Staging and scanning the immutable Loopdy plugin revision.",
            )
            _checkout_revision(SOURCE_URL, target, staged_repo, manager.hermes_home)
            _validate_staged_plugin(staged_repo, manager.hermes_home)

            backup_root = manager.data_root / "backups" / operation_id
            manager._worker_transition(
                operation_id,
                "backing_up",
                "Saving the previous Loopdy plugin installation for recovery.",
                prior_revision=prior_revision,
                backup_path=str(backup_root),
            )
            _backup_installation(manager, backup_root)

            manager._worker_transition(
                operation_id,
                "installing",
                "Installing the validated Loopdy plugin revision.",
            )
            _install_revision(manager, target)

        if _metadata_revision(manager.plugin_root) != target:
            raise UpdateFailed("Installer did not record the intended revision")
        manager._worker_transition(
            operation_id,
            "installed",
            "The Loopdy plugin update is installed.",
        )

    operation = manager._worker_operation(operation_id)
    if operation.get("restart") is not True:
        manager._worker_transition(
            operation_id,
            "installed_restart_required",
            "The update is installed. Restart the Hermes gateway to activate it.",
        )
        return

    # This timestamp is the duplicate guard. Once persisted, no recovery path
    # issues another blind restart; it only observes activation evidence.
    if not int(operation.get("restart_requested_at") or 0):
        manager._worker_transition(
            operation_id,
            "restart_requested",
            "Requesting one Hermes gateway restart to activate the update.",
            restart_requested_at=int(time.time()),
        )
        restart_state = _restart_gateway(manager)
        manager._worker_transition(
            operation_id,
            restart_state,
            (
                "The gateway restart was requested. Waiting for the updated runtime and Link response."
                if restart_state == "awaiting_activation"
                else "The restart result is ambiguous. Observing activation without issuing another restart."
            ),
        )
    else:
        manager._worker_transition(
            operation_id,
            "reconnecting",
            "A restart was already requested. Observing activation without issuing another restart.",
        )

    _wait_for_activation(manager, operation_id)


def _resolve_target_revision(hermes_home: Path) -> str:
    result = _run_capture(
        ["git", "ls-remote", SOURCE_URL, f"refs/heads/{SOURCE_BRANCH}"],
        timeout=30,
        env=_process_env(hermes_home, git=True),
    )
    if result.returncode != 0:
        raise UpdateFailed("Could not resolve the fixed update source")
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[1] != f"refs/heads/{SOURCE_BRANCH}":
        raise UpdateFailed("The fixed update source returned an invalid branch result")
    revision = fields[0].lower()
    if not _REVISION.fullmatch(revision):
        raise UpdateFailed("The fixed update source returned an invalid revision")
    return revision


def _recognized_installation(manager: PluginUpdateManager) -> tuple[str, str, str]:
    if (manager.plugin_root / ".git").is_dir():
        env = _process_env(manager.hermes_home, git=True)
        head = _run_capture(
            ["git", "-C", str(manager.plugin_root), "rev-parse", "HEAD"],
            timeout=10,
            env=env,
        )
        remote = _run_capture(
            ["git", "-C", str(manager.plugin_root), "remote", "get-url", "origin"],
            timeout=10,
            env=env,
        )
        dirty = _run_capture(
            ["git", "-C", str(manager.plugin_root), "status", "--porcelain", "--untracked-files=all"],
            timeout=15,
            env=env,
        )
        revision = head.stdout.strip().lower()
        remote_value = remote.stdout.strip()
        if (
            head.returncode != 0
            or remote.returncode != 0
            or dirty.returncode != 0
            or dirty.stdout.strip()
            or not _REVISION.fullmatch(revision)
            or not _is_github_repository(remote_value, "promptclickrun/loopdy-plugin")
        ):
            raise UpdateBlocked("Installed Git checkout is dirty or unrecognized")
        return revision, SOURCE_URL, ""

    metadata_path = manager.hermes_home / "plugins" / ".install-metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        entry = metadata.get(PLUGIN_NAME) if isinstance(metadata, dict) else None
    except (OSError, ValueError) as exc:
        raise UpdateBlocked("Install metadata is unavailable") from exc
    if not isinstance(entry, dict):
        raise UpdateBlocked("Install metadata is unavailable")
    revision = str(entry.get("revision") or "").lower()
    source = str(entry.get("source") or "")
    if not _REVISION.fullmatch(revision):
        raise UpdateBlocked("Installed revision is unrecognized")

    source_without_fragment, separator, subdir = source.partition("#")
    parsed = urlsplit(source_without_fragment)
    if (
        _is_github_repository(source_without_fragment, "promptclickrun/loopdy-plugin")
        and not separator
    ):
        return revision, SOURCE_URL, ""
    if (
        _is_github_repository(source_without_fragment, "promptclickrun/loopdy-ios")
        and subdir == "plugins/loopdy"
    ):
        return revision, "https://github.com/promptclickrun/loopdy-ios", subdir
    # The coordinated app release installs from a committed file:// checkout.
    # Its metadata still names the canonical plugin subdirectory; verify bytes
    # against the authoritative app repository at the recorded commit.
    if parsed.scheme == "file" and subdir == "plugins/loopdy":
        return revision, "https://github.com/promptclickrun/loopdy-ios", subdir
    raise UpdateBlocked("Installed Loopdy source is unrecognized")


def _is_github_repository(value: str, repository: str) -> bool:
    normalized = value.strip().rstrip("/").removesuffix(".git")
    parsed = urlsplit(normalized)
    if parsed.scheme in {"https", "ssh"}:
        return parsed.hostname == "github.com" and parsed.path.strip("/") == repository
    return normalized in {
        f"git@github.com:{repository}",
        f"github.com:{repository}",
    }


def _verify_installed_tree(
    manager: PluginUpdateManager,
    *,
    revision: str,
    source_url: str,
    subdir: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="verify.", dir=manager.data_root) as directory:
        repository = Path(directory) / "repo"
        _checkout_revision(source_url, revision, repository, manager.hermes_home)
        reference = repository / subdir if subdir else repository
        if _tree_digest(reference) != _tree_digest(manager.plugin_root):
            raise UpdateBlocked("Installed Loopdy files are locally modified")


def _checkout_revision(
    source_url: str,
    revision: str,
    destination: Path,
    hermes_home: Path,
) -> None:
    env = _process_env(hermes_home, git=True)
    commands = (
        ["git", "init", "--quiet", str(destination)],
        ["git", "-C", str(destination), "remote", "add", "origin", source_url],
        ["git", "-C", str(destination), "fetch", "--quiet", "--depth", "1", "origin", revision],
        ["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    )
    for command in commands:
        result = _run_quiet(command, timeout=75, env=env)
        if result != 0:
            raise UpdateFailed("Could not stage an immutable plugin revision")
    actual = _run_capture(
        ["git", "-C", str(destination), "rev-parse", "HEAD"],
        timeout=10,
        env=env,
    )
    if actual.returncode != 0 or actual.stdout.strip().lower() != revision:
        raise UpdateFailed("Staged plugin revision did not match its immutable target")


def _validate_staged_plugin(plugin_root: Path, hermes_home: Path) -> None:
    manifest_path = plugin_root / "plugin.yaml"
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UpdateBlocked("Staged plugin manifest is unavailable") from exc
    if not re.search(r"(?m)^name:\s*loopdy\s*$", manifest_text):
        raise UpdateBlocked("Staged plugin identity is not Loopdy")

    # Added privileges require an attended host decision before replacing code.
    try:
        import yaml
        staged_manifest = yaml.safe_load(manifest_text)
        previous_manifest = yaml.safe_load((hermes_home / "plugins" / PLUGIN_NAME / "plugin.yaml").read_text(encoding="utf-8"))
        def declared(value: Any) -> set[str]:
            if not isinstance(value, dict):
                raise ValueError("Invalid manifest")
            caps = value.get("capabilities", [])
            if not isinstance(caps, list) or not all(isinstance(cap, str) for cap in caps):
                raise ValueError("Invalid capabilities")
            return set(caps)
        if declared(staged_manifest) - declared(previous_manifest):
            raise UpdateBlocked("New plugin capabilities require host approval")
    except UpdateBlocked:
        raise
    except Exception as exc:
        raise UpdateBlocked("Plugin capability comparison could not complete") from exc

    try:
        from tools.plugin_guard import scan_plugin, should_allow_plugin_install

        scan = scan_plugin(plugin_root, source=SOURCE_URL)
        allowed, _reason = should_allow_plugin_install(scan, force=False)
    except Exception as exc:
        raise UpdateBlocked("Plugin security scan could not complete") from exc
    if allowed is not True:
        # Caution needs an attended operator decision; dangerous is always blocked.
        raise UpdateBlocked("Plugin security scan requires operator review")

    result = _run_quiet(
        [
            sys.executable,
            "-m",
            "hermes_cli.main",
            "plugins",
            "doctor",
            str(plugin_root),
            "--ci",
        ],
        timeout=90,
        env=_process_env(hermes_home),
    )
    if result != 0:
        raise UpdateBlocked("Plugin Doctor rejected the staged revision")


def _backup_installation(manager: PluginUpdateManager, backup_root: Path) -> None:
    if backup_root.exists():
        if not (backup_root / "plugin" / "plugin.yaml").is_file():
            raise UpdateBlocked("The existing recovery backup is invalid")
        return
    backup_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = backup_root.with_name(backup_root.name + ".tmp")
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(mode=0o700)
    try:
        shutil.copytree(
            manager.plugin_root,
            temporary / "plugin",
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
        )
        metadata = manager.hermes_home / "plugins" / ".install-metadata.json"
        if metadata.is_file():
            shutil.copy2(metadata, temporary / ".install-metadata.json")
        os.replace(temporary, backup_root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _install_revision(manager: PluginUpdateManager, revision: str) -> None:
    result = _run_quiet(
        [
            sys.executable,
            "-m",
            "hermes_cli.main",
            "plugins",
            "install",
            SOURCE_URL,
            "--ref",
            revision,
            "--force",
            "--no-enable",
        ],
        timeout=180,
        env=_process_env(manager.hermes_home),
    )
    if result != 0:
        raise UpdateFailed("Hermes plugin installer rejected the staged revision")


def _restart_gateway(manager: PluginUpdateManager) -> str:
    command = [sys.executable, "-m", "hermes_cli.main"]
    if manager.profile != "default":
        command.extend(["--profile", manager.profile])
    command.extend(["gateway", "restart"])
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=210,
            check=False,
            env=_process_env(manager.hermes_home),
        )
    except subprocess.TimeoutExpired:
        return "reconnecting"
    # A non-zero lifecycle command can still have committed the restart. Once
    # requested, observation is the only safe action regardless of exit status.
    return "awaiting_activation" if result.returncode == 0 else "reconnecting"


def _wait_for_activation(manager: PluginUpdateManager, operation_id: str) -> None:
    deadline = time.monotonic() + _ACTIVATION_WAIT_SECONDS
    while time.monotonic() < deadline:
        status = manager.status(operation_id=operation_id)
        if status["phase"] == "complete":
            return
        time.sleep(1.0)
    _transition_if_possible(
        manager,
        operation_id,
        "timed_out",
        "Activation is still unconfirmed. Reconnect and check this operation again; no second restart was requested.",
    )


def _tree_digest(root: Path) -> str:
    if not root.is_dir():
        raise UpdateBlocked("Plugin tree is unavailable")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__", ".DS_Store"} for part in relative.parts):
            continue
        if path.suffix == ".pyc":
            continue
        name = relative.as_posix().encode("utf-8")
        if path.is_symlink():
            digest.update(b"L\0" + name + b"\0" + os.readlink(path).encode("utf-8") + b"\0")
        elif path.is_file():
            digest.update(b"F\0" + name + b"\0")
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            digest.update(b"\0")
        elif path.is_dir():
            digest.update(b"D\0" + name + b"\0")
        else:
            raise UpdateBlocked("Plugin tree contains an unsupported filesystem entry")
    return digest.hexdigest()


def _process_env(hermes_home: Path, *, git: bool = False) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "HERMES_HOME": str(hermes_home),
        "LANG": "C.UTF-8",
        "PYTHONUTF8": "1",
    }
    if git:
        env.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/usr/bin/false",
                "GCM_INTERACTIVE": "Never",
            }
        )
    return env


def _run_quiet(command: list[str], *, timeout: int, env: dict[str, str]) -> int:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateFailed("A bounded updater command could not complete") from exc
    return result.returncode


def _run_capture(
    command: list[str], *, timeout: int, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateFailed("A bounded updater command could not complete") from exc
    if len(result.stdout.encode("utf-8", errors="replace")) > _MAX_CAPTURE:
        raise UpdateFailed("Updater command output exceeded its bound")
    return result


def _transition_if_possible(
    manager: PluginUpdateManager,
    operation_id: str,
    phase: str,
    message: str,
) -> None:
    try:
        # A terminal phase or a later successful runtime owns the journal.
        current = manager._worker_operation(operation_id)
        if current.get("phase") == "complete":
            return
        manager._worker_transition(operation_id, phase, message)
    except Exception:
        pass


def _remove_launchd_job(label: str) -> None:
    if not re.fullmatch(r"app\.loopdy\.plugin-update\.[0-9]+\.[0-9a-f]{20}", label):
        return
    launchctl = shutil.which("launchctl")
    if not launchctl:
        return
    try:
        subprocess.run(
            [launchctl, "remove", label],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(Path.home()),
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


if __name__ == "__main__":
    raise SystemExit(main())
