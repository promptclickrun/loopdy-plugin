"""Loopdy management surface over Hermes' canonical personality owner."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

from hermes_cli.config import read_user_config_raw
from hermes_cli.personality import (
    BUILTIN_PERSONALITIES,
    active_personality_name,
    available_personalities,
    describe_personality,
    persist_personality,
    render_personality_prompt,
    resolve_personality,
)
from utils import atomic_roundtrip_yaml_update

from .link_contracts import PersonalityRequest


class PersonalityCatalogManager:
    def __init__(
        self,
        *,
        config_path: Path,
        persist_selection: Callable[[str], Any] = persist_personality,
    ):
        self.config_path = Path(config_path).expanduser().resolve()
        self.persist_selection = persist_selection

    def snapshot(self) -> dict[str, Any]:
        raw = read_user_config_raw(self.config_path)
        custom = ((raw.get("agent") or {}).get("personalities") or {})
        if not isinstance(custom, dict):
            custom = {}
        available = available_personalities(raw)
        entries = []
        for name, value in available.items():
            structured = value if isinstance(value, dict) else {}
            entries.append(
                {
                    "name": name,
                    # Hermes appends a three-character ellipsis after `width`
                    # when truncating. Reserve that space so the canonical
                    # preview always fits Loopdy Link's 240-character field.
                    "description": describe_personality(value, width=237),
                    "systemPrompt": render_personality_prompt(value),
                    "tone": str(structured.get("tone") or "").strip(),
                    "style": str(structured.get("style") or "").strip(),
                    "builtIn": name in BUILTIN_PERSONALITIES,
                    "customized": name in custom,
                }
            )
        entries.sort(key=lambda item: (not item["builtIn"], item["name"]))
        return {
            "revision": self._revision(raw),
            "activeName": active_personality_name(raw),
            "personalities": entries,
        }

    def mutate(self, request: PersonalityRequest) -> dict[str, Any]:
        if request.action == "catalog":
            return self.snapshot()
        current = self.snapshot()
        if request.expected_revision != current["revision"]:
            raise ValueError("The personality catalog changed. Reload and try again.")
        raw = read_user_config_raw(self.config_path)
        agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        custom = dict(agent.get("personalities") or {})

        if request.action == "save":
            if request.definition is None or request.name is None:
                raise ValueError("The personality definition is missing")
            original = request.definition.get("originalName")
            if original and original != request.name:
                custom.pop(original, None)
            custom[request.name] = {
                "description": request.definition["description"],
                "system_prompt": request.definition["systemPrompt"],
                "tone": request.definition["tone"],
                "style": request.definition["style"],
            }
            self._write_custom(custom)
            if current["activeName"] == original:
                self._persist_active(request.name)
        elif request.action == "delete":
            if request.name not in custom:
                raise ValueError("Only a custom personality or override can be removed")
            custom.pop(request.name, None)
            self._write_custom(custom)
            if current["activeName"] == request.name:
                self._persist_active("")
        elif request.action == "activate":
            name, _ = resolve_personality(request.name or "", raw)
            self._persist_active(name)
        else:
            raise ValueError("The personality action is unsupported")
        return self.snapshot()

    def _write_custom(self, personalities: dict[str, Any]) -> None:
        atomic_roundtrip_yaml_update(
            self.config_path,
            "agent.personalities",
            personalities,
        )
        try:
            os.chmod(self.config_path, 0o600)
        except (OSError, NotImplementedError):
            pass

    def _persist_active(self, name: str) -> None:
        if self.persist_selection(name) is False:
            raise ValueError("Hermes could not save the active personality")

    @staticmethod
    def _revision(raw: dict[str, Any]) -> int:
        relevant = {
            "active": ((raw.get("display") or {}).get("personality") or ""),
            "personalities": ((raw.get("agent") or {}).get("personalities") or {}),
        }
        encoded = json.dumps(
            relevant,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return int.from_bytes(hashlib.sha256(encoded).digest()[:8], "big") & ((1 << 63) - 1)


__all__ = ["PersonalityCatalogManager"]
