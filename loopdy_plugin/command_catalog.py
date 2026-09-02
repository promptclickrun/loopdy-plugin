"""Hermes-owned slash command metadata for Loopdy chat composers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


_COMMAND_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,95}$")
_ARGUMENT_MODES = {"none", "text", "options", "mixed"}


def build_command_catalog(
    *,
    registry: list[Any] | tuple[Any, ...] | None = None,
    gateway_names: set[str] | frozenset[str] | None = None,
    plugin_commands: Mapping[str, Any] | None = None,
    skill_commands: Mapping[str, Any] | None = None,
    quick_commands: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return metadata only, in the same precedence order Hermes dispatches."""
    if registry is None or gateway_names is None:
        from hermes_cli.commands import COMMAND_REGISTRY, GATEWAY_KNOWN_COMMANDS

        registry = COMMAND_REGISTRY if registry is None else registry
        gateway_names = GATEWAY_KNOWN_COMMANDS if gateway_names is None else gateway_names
    if quick_commands is None:
        from cli import load_cli_config

        loaded = load_cli_config().get("quick_commands", {})
        quick_commands = loaded if isinstance(loaded, Mapping) else {}
    if plugin_commands is None:
        from hermes_cli.plugins import get_plugin_commands

        plugin_commands = get_plugin_commands()
    if skill_commands is None:
        from agent.skill_commands import get_skill_commands

        skill_commands = get_skill_commands()

    rows: list[dict[str, Any]] = []
    claimed: set[str] = set()

    for command in registry:
        name = _name(getattr(command, "name", ""))
        aliases = tuple(
            alias
            for alias in (_name(value) for value in getattr(command, "aliases", ()))
            if alias
        )
        if not name or name not in gateway_names:
            continue
        rows.append(
            _row(
                name=name,
                description=getattr(command, "description", ""),
                category=getattr(command, "category", "Hermes"),
                args_hint=getattr(command, "args_hint", ""),
                aliases=aliases,
                argument_mode=getattr(command, "argument_mode", None),
                source="core",
            )
        )
        claimed.update((name, *aliases))

    # Hermes checks quick commands before plugins and skills.
    for name, metadata in sorted(quick_commands.items()):
        command_name = _name(name)
        if not command_name or command_name in claimed or not isinstance(metadata, Mapping):
            continue
        rows.append(
            _row(
                name=command_name,
                description=metadata.get("description") or "Run a saved command",
                category="Saved commands",
                args_hint=metadata.get("args_hint") or "",
                aliases=(),
                argument_mode=metadata.get("argument_mode"),
                source="user",
            )
        )
        claimed.add(command_name)

    for name, metadata in sorted(plugin_commands.items()):
        command_name = _name(name)
        if not command_name or command_name in claimed or not isinstance(metadata, Mapping):
            continue
        rows.append(
            _row(
                name=command_name,
                description=metadata.get("description") or "Run a plugin command",
                category="Plugins",
                args_hint=metadata.get("args_hint") or "",
                aliases=(),
                argument_mode=metadata.get("argument_mode"),
                source="plugin",
            )
        )
        claimed.add(command_name)

    for command_key, metadata in sorted(skill_commands.items()):
        command_name = _name(str(command_key).lstrip("/"))
        if not command_name or command_name in claimed or not isinstance(metadata, Mapping):
            continue
        rows.append(
            _row(
                name=command_name,
                description=metadata.get("description") or f"Use the {command_name} skill",
                category="Skills",
                args_hint="[instruction]",
                aliases=(),
                argument_mode="text",
                source="skill",
            )
        )
        claimed.add(command_name)

    return rows[:1_000]


def _row(
    *,
    name: str,
    description: Any,
    category: Any,
    args_hint: Any,
    aliases: tuple[str, ...],
    argument_mode: Any,
    source: str,
) -> dict[str, Any]:
    hint = _single_line(args_hint, 240)
    mode = str(argument_mode or "").strip().lower()
    if mode not in _ARGUMENT_MODES:
        mode = "text" if hint else "none"
    return {
        "name": name,
        "description": _single_line(description, 240) or f"Run /{name}",
        "category": _single_line(category, 80) or "Hermes",
        "argsHint": hint,
        "aliases": list(aliases),
        "argumentMode": mode,
        "source": source,
        "requiresArguments": hint.startswith("<"),
    }


def _name(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "-")
    return normalized if _COMMAND_NAME.fullmatch(normalized) else ""


def _single_line(value: Any, maximum: int) -> str:
    return " ".join(str(value or "").split())[:maximum]


__all__ = ["build_command_catalog"]
