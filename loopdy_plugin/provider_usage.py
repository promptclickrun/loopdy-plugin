"""Host-side discovery of installed AI coding tools and their local usage.

Secret-safe by construction:

- Auth and config files are checked for existence only. Their contents are
  never read, parsed, or included in any output.
- Transcript and session ledgers are parsed for numeric usage fields only
  (token counts, timestamps, model identifiers). Message text, prompts,
  file contents, and auth material are never extracted.
- Scans are bounded by file count, per-file size, and total bytes.
- A failure in one provider never breaks discovery of the others.

The usage contract distinguishes three states per provider, matching the
provider usage evaluation: "installed", "usage available" (with an explicit
source), and "usage unavailable" (with a reason). The plugin never guesses
or fabricates usage numbers.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "loopdy.provider_discovery"
SCHEMA_VERSION = 1

# Scan budgets. Transcripts and rollouts can grow large; stay bounded.
_MAX_LEDGER_FILES = 400
_MAX_LEDGER_FILE_BYTES = 10_000_000
_MAX_LEDGER_TOTAL_BYTES = 100_000_000
_MAX_VERSION_LEN = 80
_MAX_MODELS = 20
_COMMAND_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class _ProviderDef:
    id: str
    display_name: str
    binaries: tuple[str, ...] = ()
    config_markers: tuple[str, ...] = ()
    auth_markers: tuple[str, ...] = ()
    env_markers: tuple[str, ...] = ()
    usage_source: str | None = None
    usage_unavailable_reason: str = ""


_PROVIDERS: tuple[_ProviderDef, ...] = (
    _ProviderDef(
        id="claude_code",
        display_name="Claude Code",
        binaries=("claude",),
        config_markers=("~/.claude.json", "~/.claude/settings.json"),
        auth_markers=("~/.claude/.credentials.json",),
        usage_source="local_transcripts",
    ),
    _ProviderDef(
        id="codex",
        display_name="Codex CLI",
        binaries=("codex",),
        config_markers=("~/.codex/config.toml",),
        auth_markers=("~/.codex/auth.json",),
        usage_source="local_sessions",
    ),
    _ProviderDef(
        id="copilot_cli",
        display_name="GitHub Copilot CLI",
        binaries=("copilot", "gh"),
        config_markers=("~/.config/gh/hosts.yml", "~/.copilot/"),
        auth_markers=("~/.config/gh/hosts.yml",),
        usage_unavailable_reason=(
            "GitHub exposes Copilot usage through the organization API only; "
            "there is no host-local usage ledger."
        ),
    ),
    _ProviderDef(
        id="opencode",
        display_name="OpenCode",
        binaries=("opencode",),
        config_markers=("~/.config/opencode/opencode.json",),
        auth_markers=("~/.config/opencode/auth.json",),
        usage_source="local_sessions",
    ),
    _ProviderDef(
        id="gemini_cli",
        display_name="Gemini CLI",
        binaries=("gemini",),
        config_markers=("~/.muse/settings.json",),
        auth_markers=("~/.muse/oauth_creds.json",),
        usage_unavailable_reason=(
            "Gemini CLI does not keep a host-local usage ledger."
        ),
    ),
    _ProviderDef(
        id="cursor",
        display_name="Cursor",
        binaries=("cursor-agent", "cursor"),
        config_markers=("~/.cursor/",),
        usage_unavailable_reason=(
            "Cursor usage is only available through the cursor.com dashboard API."
        ),
    ),
    _ProviderDef(
        id="aider",
        display_name="Aider",
        binaries=("aider",),
        env_markers=(
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
            "AZURE_OPENAI_API_KEY",
        ),
        usage_unavailable_reason=(
            "Aider passes provider API keys through and keeps no local usage ledger."
        ),
    ),
)

_PROVIDER_IDS = frozenset(p.id for p in _PROVIDERS)


def _resolve(home: Path, marker: str) -> Path:
    text = marker[2:] if marker.startswith("~/") else marker
    return home / text


def _marker_present(home: Path, marker: str) -> bool:
    try:
        return _resolve(home, marker).exists()
    except OSError:
        return False


def _binary_version(binary: str) -> str | None:
    path = shutil.which(binary)
    if not path:
        return None
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (proc.stdout or proc.stderr or "").strip().splitlines()
    if not output:
        return None
    return output[0].strip()[:_MAX_VERSION_LEN] or None


def _as_utc(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        # Accept epoch seconds or milliseconds.
        epoch = value / 1000.0 if value > 1e12 else float(value)
        try:
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _iter_ledger_files(root: Path, pattern: str) -> list[Path]:
    try:
        if not root.is_dir():
            return []
    except OSError:
        return []
    files: list[Path] = []
    total = 0
    try:
        candidates = sorted(root.rglob(pattern))
    except OSError:
        return []
    for candidate in candidates:
        if len(files) >= _MAX_LEDGER_FILES:
            break
        try:
            if not candidate.is_file():
                continue
            size = candidate.stat().st_size
        except OSError:
            continue
        if size > _MAX_LEDGER_FILE_BYTES:
            continue
        if total + size > _MAX_LEDGER_TOTAL_BYTES:
            break
        files.append(candidate)
        total += size
    return files


def _sum_claude_transcripts(home: Path, since: datetime) -> dict[str, Any] | None:
    """Sum token usage from Claude Code's local JSONL transcripts."""
    root = home / ".claude" / "projects"
    files = _iter_ledger_files(root, "*.jsonl")
    if not files:
        return None
    totals = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0,
              "cache_creation_input_tokens": 0}
    models: dict[str, int] = {}
    sessions = 0
    for path in files:
        session_tokens = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(record, dict) or record.get("type") != "assistant":
                        continue
                    stamp = _as_utc(record.get("timestamp"))
                    if stamp is None or stamp < since:
                        continue
                    message = record.get("message")
                    if not isinstance(message, dict):
                        continue
                    usage = message.get("usage")
                    if not isinstance(usage, dict):
                        continue
                    for key in totals:
                        value = usage.get(key)
                        if isinstance(value, int) and value >= 0:
                            totals[key] += value
                            session_tokens += value
                    model = message.get("model")
                    if isinstance(model, str) and model:
                        short = model[:120]
                        if len(models) < _MAX_MODELS or short in models:
                            models[short] = models.get(short, 0) + 1
        except OSError:
            continue
        if session_tokens:
            sessions += 1
    if not any(totals.values()):
        return None
    return {**totals, "sessions": sessions, "models": models}


def _sum_codex_rollouts(home: Path, since: datetime) -> dict[str, Any] | None:
    """Sum token usage from Codex CLI's local session rollout files."""
    root = home / ".codex" / "sessions"
    files = _iter_ledger_files(root, "rollout-*.jsonl")
    if not files:
        return None
    totals = {"input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0}
    sessions = 0
    for path in files:
        session_tokens = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(record, dict):
                        continue
                    stamp = _as_utc(record.get("timestamp"))
                    if stamp is None or stamp < since:
                        continue
                    payload = record.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    if payload.get("type") != "token_count":
                        continue
                    info = payload.get("info")
                    if not isinstance(info, dict):
                        continue
                    # last_token_usage is the delta for the event; total_token_usage
                    # is cumulative, so only sum the deltas.
                    usage = info.get("last_token_usage")
                    if not isinstance(usage, dict):
                        continue
                    for key in totals:
                        value = usage.get(key)
                        if isinstance(value, int) and value >= 0:
                            totals[key] += value
                            session_tokens += value
        except OSError:
            continue
        if session_tokens:
            sessions += 1
    if not any(totals.values()):
        return None
    return {**totals, "sessions": sessions}


def _sum_opencode_sessions(home: Path, since: datetime) -> dict[str, Any] | None:
    """Sum token usage from OpenCode's local session storage, if present."""
    root = home / ".local" / "share" / "opencode"
    files = _iter_ledger_files(root, "part-*.json")
    if not files:
        return None
    totals = {"input_tokens": 0, "output_tokens": 0}
    sessions: set[str] = set()
    for path in files:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        if mtime < since:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                part = json.load(handle)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(part, dict):
            continue
        tokens = part.get("tokens")
        if not isinstance(tokens, dict):
            continue
        found = False
        for key in totals:
            value = tokens.get(key)
            if isinstance(value, int) and value >= 0:
                totals[key] += value
                found = True
        if found and len(path.parts) >= 4:
            # .../session/<session_id>/message/<message_id>/part-*.json
            sessions.add(path.parts[-4])
    if not any(totals.values()):
        return None
    return {**totals, "sessions": len(sessions)}


_USAGE_READERS = {
    "claude_code": _sum_claude_transcripts,
    "codex": _sum_codex_rollouts,
    "opencode": _sum_opencode_sessions,
}


def discover_providers(
    *,
    home: Path | str | None = None,
    include_usage: bool = True,
    usage_days: int = 7,
) -> dict[str, Any]:
    """Discover installed AI coding tools on the Hermes host.

    Returns a bounded JSON-serializable payload. Auth material is never read;
    only marker existence and numeric usage fields are reported.
    """
    base = Path(home).expanduser() if home is not None else Path.home()
    days = max(1, min(int(usage_days), 30))
    since = datetime.now(timezone.utc) - timedelta(days=days)
    providers: list[dict[str, Any]] = []
    for definition in _PROVIDERS:
        try:
            providers.append(_describe_provider(definition, base, since, include_usage, days))
        except Exception:  # noqa: BLE001 - one provider must not break discovery
            providers.append(
                {
                    "id": definition.id,
                    "display_name": definition.display_name,
                    "installed": False,
                    "version": None,
                    "authenticated": False,
                    "config_present": False,
                    "usage": {"available": False, "reason": "discovery failed for this provider"},
                }
            )
    return {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "usage_window_days": days,
        "providers": providers,
    }


def _describe_provider(
    definition: _ProviderDef,
    home: Path,
    since: datetime,
    include_usage: bool,
    days: int,
) -> dict[str, Any]:
    version: str | None = None
    installed = False
    for binary in definition.binaries:
        found = _binary_version(binary)
        if found is not None:
            installed = True
            if version is None:
                version = found
    config_present = any(_marker_present(home, m) for m in definition.config_markers)
    authenticated = any(_marker_present(home, m) for m in definition.auth_markers)
    if not authenticated and definition.env_markers:
        authenticated = any(name in os.environ for name in definition.env_markers)
    # Copilot CLI may ride on the gh extension instead of a standalone binary.
    if not installed and definition.id == "copilot_cli" and shutil.which("gh"):
        try:
            proc = subprocess.run(
                ["gh", "extension", "list"],
                capture_output=True,
                text=True,
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
            if "copilot" in (proc.stdout or "").lower():
                installed = True
        except (OSError, subprocess.SubprocessError):
            pass
    usage: dict[str, Any] | None = None
    if include_usage:
        usage = _provider_usage(definition, home, since, days)
    return {
        "id": definition.id,
        "display_name": definition.display_name,
        "installed": installed,
        "version": version,
        "authenticated": authenticated,
        "config_present": config_present,
        "usage": usage,
    }


def _provider_usage(
    definition: _ProviderDef,
    home: Path,
    since: datetime,
    days: int,
) -> dict[str, Any]:
    reader = _USAGE_READERS.get(definition.id)
    if reader is None:
        return {
            "available": False,
            "reason": definition.usage_unavailable_reason or "usage is not available for this provider",
        }
    try:
        totals = reader(home, since)
    except Exception:  # noqa: BLE001 - usage parsing must not break discovery
        totals = None
    if not totals:
        return {
            "available": False,
            "reason": (
                f"no local usage ledger found for {definition.display_name} "
                f"in the last {days} day(s)"
            ),
        }
    total_tokens = sum(v for k, v in totals.items() if k.endswith("_tokens") and isinstance(v, int))
    return {
        "available": True,
        "source": definition.usage_source,
        "window_days": days,
        "total_tokens": total_tokens,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **totals,
    }


def get_provider_usage(
    provider_id: str,
    *,
    home: Path | str | None = None,
    usage_days: int = 7,
) -> dict[str, Any]:
    """Return the usage block for a single known provider id."""
    normalized = str(provider_id or "").strip().lower()
    if normalized not in _PROVIDER_IDS:
        return {"available": False, "reason": f"unknown provider id: {normalized[:64]}"}
    definition = next(p for p in _PROVIDERS if p.id == normalized)
    base = Path(home).expanduser() if home is not None else Path.home()
    days = max(1, min(int(usage_days), 30))
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return _provider_usage(definition, base, since, days)


__all__ = ["discover_providers", "get_provider_usage"]
