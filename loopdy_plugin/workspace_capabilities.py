"""Finite capability settings bridge; called only after Link authorization.

No config document is accepted or returned. Hermes' own public dashboard
services own persistence. Configured state is not a claim of runtime activation.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import importlib
import inspect
import json
from typing import Any


@contextmanager
def profile_scope(agent_id: str):
    """Use Hermes' context-local home API, never process environment/globals."""
    from hermes_cli.profiles import get_profile_dir, profile_exists
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override

    if not profile_exists(agent_id):
        raise ValueError("The selected Hermes profile no longer exists")
    token = set_hermes_home_override(get_profile_dir(agent_id))
    try:
        yield
    finally:
        reset_hermes_home_override(token)


def _has(module: str, name: str, *parameters: str) -> bool:
    try:
        function = getattr(importlib.import_module(module), name)
        return callable(function) and set(parameters).issubset(inspect.signature(function).parameters)
    except (ImportError, AttributeError, TypeError, ValueError):
        return False


def editor_capabilities() -> dict[str, Any]:
    module = "hermes_cli.web_routers.skills"
    return {
        "version": 2,
        "read": _has(module, "get_skill_content", "name", "profile"),
        "create": _has(module, "create_skill", "body"),
        "update": _has(module, "update_skill_content", "body"),
        "import": _has(module, "create_skill", "body"),
    }


def revision(agent_id: str, kind: str, item_id: str, enabled: bool, scope: str, activation: str, reason: str) -> str:
    value = json.dumps([agent_id, kind, item_id, enabled, scope, activation, reason], separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()


def control(agent_id: str, kind: str, item: dict[str, Any]) -> dict[str, Any]:
    item_id = item["id"]
    reason = ""
    scope = "Selected profile · all platforms"
    activation = "Saved settings apply to new Hermes sessions; existing conversations are unchanged."
    supported = False
    if kind == "skill":
        supported = _has("hermes_cli.web_routers.skills", "toggle_skill", "body", "profile")
        activation = "Saved global skill policy applies to new sessions. Platform-specific restrictions may still disable this skill."
        try:
            from agent.skill_utils import ESSENTIAL_SKILLS
            if item_id in ESSENTIAL_SKILLS:
                reason = "Hermes protects this essential skill; it cannot be disabled."
        except ImportError:
            supported = False
    elif kind == "mcpServer":
        supported = _has("hermes_cli.web_routers.mcp", "set_mcp_server_enabled", "name", "body", "profile")
        activation = "Saved settings apply after a new session or host-managed MCP reload. No reload is performed here."
    elif kind == "plugin":
        supported = _has("hermes_cli.plugins_cmd", "dashboard_set_agent_plugin_enabled", "name", "enabled")
        activation = "Saved plugin policy requires a Hermes host restart. Running plugins are not unloaded here."
        # Non-agent providers can control auth, secret resolution, memory or the
        # active transport. Their dedicated host setup remains authoritative.
        if item.get("kind") != "standalone":
            reason = "Provider and platform plugins must be managed through Hermes host setup."
        if item_id == item.get("name") and item.get("identityAmbiguous") is True:
            reason = "This bare plugin identity is ambiguous. Manage it by its qualified key in Hermes."
        if item.get("controlReason"):
            reason = item["controlReason"]
    elif kind == "toolset":
        supported = _has("hermes_cli.web_routers.tools", "toggle_toolset", "name", "body", "profile")
        scope = "Selected profile · " + item.get("platform", "cli")
        activation = "Saved toolset policy applies to new sessions on this platform, not existing chats. Enabling may run Hermes provider setup."
    # Never permit a remote UI to cut the channel which carries its receipt.
    if "loopdy" in item_id.lower().replace("_", "-").split("/") or item_id.lower().startswith("loopdy"):
        reason = "Loopdy is locked because it carries this control connection. Manage it locally on the host."
    if not supported and not reason:
        reason = "This Hermes version does not expose the supported enable/disable API. Update the host to manage this item."
    return {
        "kind": kind, "id": item_id, "enabled": item["enabled"],
        "canToggle": supported and not reason, "reason": reason,
        "scope": scope, "activation": activation,
        "revision": revision(agent_id, kind, item_id, item["enabled"], scope, activation, reason),
    }


async def toolsets(agent_id: str) -> list[dict[str, Any]]:
    from hermes_cli.web_routers.tools import get_toolsets

    rows = await get_toolsets(profile=agent_id)
    if not isinstance(rows, list) or len(rows) > 256:
        raise ValueError("Invalid Hermes toolset catalog")
    result = []
    for row in rows:
        if not isinstance(row, dict) or type(row.get("enabled")) is not bool:
            raise ValueError("Invalid Hermes toolset")
        # Tools are represented by the host's supported configuration unit,
        # not by an invented SKILL.md editor for executable tool code.
        result.append({
            "id": row["name"], "name": row.get("label") or row["name"],
            "description": row.get("description", ""),
            "platform": row.get("platform", "cli"), "enabled": row["enabled"],
            "toolCount": len(row.get("tools", [])),
        })
    return result


async def plugins(agent_id: str) -> list[dict[str, Any]]:
    from hermes_cli.plugins import get_plugin_manager
    from hermes_cli.config import load_config

    def read():
        with profile_scope(agent_id):
            # Inventory only: do not discover/load executable plugins merely
            # to render a screen. Managers are scoped by Hermes home.
            rows = get_plugin_manager().list_plugins()
            config = load_config()
            policy = config.get("plugins", {})
            policy = policy if isinstance(policy, dict) else {}
            enabled = policy.get("enabled")
            disabled = policy.get("disabled", [])
            if enabled is not None and not isinstance(enabled, list):
                raise ValueError("Invalid plugin policy")
            if not isinstance(disabled, list):
                raise ValueError("Invalid plugin policy")
            result = []
            for source in rows:
                row = dict(source)
                aliases = {row.get("key"), row.get("name")}
                if aliases.intersection(disabled):
                    row["enabled"] = False
                    if row.get("key") != row.get("name") and row.get("name") in disabled:
                        row["controlReason"] = "A legacy bare-name deny rule also applies to this plugin. Resolve that rule in Hermes before enabling this qualified plugin."
                elif isinstance(enabled, list) and row.get("kind") == "standalone":
                    row["enabled"] = bool(aliases.intersection(enabled))
                # On older host configs without an explicit policy use the
                # manager's observed state, never invent an opt-in default.
                result.append(row)
            return result
    return await asyncio.to_thread(read)


async def set_enabled(agent_id: str, kind: str, item_id: str, enabled: bool) -> None:
    if kind == "skill":
        from hermes_cli.web_models import SkillToggle
        from hermes_cli.web_routers.skills import toggle_skill
        await toggle_skill(SkillToggle(name=item_id, enabled=enabled, profile=agent_id), profile=agent_id)
    elif kind == "mcpServer":
        from hermes_cli.web_models import MCPEnabledToggle
        from hermes_cli.web_routers.mcp import set_mcp_server_enabled
        await set_mcp_server_enabled(item_id, MCPEnabledToggle(enabled=enabled, profile=agent_id), profile=agent_id)
    elif kind == "toolset":
        from hermes_cli.web_models import ToolsetToggle
        from hermes_cli.web_routers.tools import toggle_toolset
        await toggle_toolset(item_id, ToolsetToggle(enabled=enabled, profile=agent_id), profile=agent_id)
    elif kind == "plugin":
        from hermes_cli.plugins_cmd import dashboard_set_agent_plugin_enabled
        def write():
            with profile_scope(agent_id):
                result = dashboard_set_agent_plugin_enabled(item_id, enabled=enabled)
                if not isinstance(result, dict) or result.get("ok") is not True:
                    raise ValueError("Hermes rejected the plugin setting")
        await asyncio.to_thread(write)
    else:
        raise ValueError("Unsupported capability type")
