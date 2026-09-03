"""Explicit Loopdy Link workspace controls backed by Hermes-owned services.

This module deliberately exposes a finite operation table.  It is not a
generic RPC, URL fetcher, command runner, or gateway credential bridge.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import re
import time
from collections import OrderedDict
from typing import Any

from .attachments import AttachmentStore
from .generative_ui import GenerativeUIError, validate_rendered_envelope
from .link_contracts import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENT_CHUNK_BYTES,
    WORKSPACE_OPERATIONS,
    WorkspaceRequest,
    _workspace_json,
)
from .workspace_git import WorkspaceGitError, WorkspaceGitService


class WorkspaceControlError(RuntimeError):
    """A bounded, user-safe workspace control failure."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "workspace_unavailable",
        status: str = "failed",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class WorkspaceConflictError(ValueError):
    """The requested coordinate or revision is stale."""


class _HermesMethodUnavailable(WorkspaceControlError):
    """The installed Hermes runtime does not expose a requested native RPC."""


_REASONING_VALUES = frozenset(
    {"", "none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
)
_AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CRON_SESSION = re.compile(r"^cron_(.+)_\d{8}_\d{6}$")
# Keep the projection aligned with Hermes' renderable transcript roles. The
# client uses tool_call_id and the rich fields below to group tool activity.
_HISTORY_ROLES = frozenset({"user", "assistant", "tool"})
_HISTORY_RICH_FIELDS = (
    "tool_call_id",
    "tool_calls",
    "tool_name",
    "effect_disposition",
    "timestamp",
    "token_count",
    "finish_reason",
    "reasoning",
    "reasoning_content",
    "reasoning_details",
    "codex_reasoning_items",
    "codex_message_items",
    "platform_message_id",
    "_compressed_summary",
    "display_kind",
    "display_metadata",
    "compacted",
)
_SESSION_HISTORY_OFFSET_LIMIT = 10_000_000
_SESSION_HISTORY_RESPONSE_MAX_BYTES = 160_000
_PROJECT_DIRECTORY_PAGE_LIMIT = 100
_PROJECT_DIRECTORY_OFFSET_LIMIT = 100_000
_PROJECT_DIRECTORY_HIDDEN = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".next",
    ".turbo",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
})


class HermesWorkspaceBackend:
    """Validated projections over Hermes' existing profile/config services."""

    def __init__(
        self,
        *,
        service: Any,
        clock: Any = time.time,
        clarify_timeout: Any | None = None,
        session_workspace_setter: Any | None = None,
        session_workspace_getter: Any | None = None,
        session_active_getter: Any | None = None,
        connection_id_getter: Any | None = None,
        workspace_git: WorkspaceGitService | Any | None = None,
        workspace_git_state_path: Path | str | None = None,
        attachment_store: AttachmentStore | None = None,
    ):
        self.service = service
        self.clock = clock
        self.clarify_timeout = clarify_timeout
        self.session_workspace_setter = session_workspace_setter
        self.session_workspace_getter = session_workspace_getter
        self.session_active_getter = session_active_getter
        self.connection_id_getter = connection_id_getter
        self.workspace_git = workspace_git
        self.workspace_git_state_path = Path(
            workspace_git_state_path
            or Path(os.getenv("HERMES_HOME", Path.home() / ".hermes"))
            / "plugin-data"
            / "loopdy"
            / "workspace-git-link.sqlite3"
        )
        self.attachment_store = attachment_store or AttachmentStore(
            Path(os.getenv("HERMES_HOME", Path.home() / ".hermes"))
            / "plugin-data"
            / "loopdy"
            / "agent-attachments.sqlite3"
        )
        self._project_git_services: OrderedDict[
            tuple[str, str, str, str], WorkspaceGitService
        ] = OrderedDict()

    async def agents_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        _empty_payload(payload)
        records = await self._profile_records()
        if not isinstance(records, list) or len(records) > 128:
            raise WorkspaceControlError("Hermes returned an invalid agent catalog")
        agents = []
        for record in records:
            if not isinstance(record, dict):
                raise WorkspaceControlError("Hermes returned an invalid agent catalog")
            agent_id = _agent_id(record.get("id"))
            display_name = _text(
                record.get("ui_display_name") or record.get("display_name"),
                80,
                allow_empty=True,
            )
            description = _text(record.get("description"), 4_096, allow_empty=True)
            role = _utf8_prefix(description, 160) or "Hermes agent"
            soul = await self._profile_soul(agent_id)
            agent = {
                "id": agent_id,
                "name": display_name or _display_name(agent_id),
                "role": role,
                "summary": description or "Hermes agent",
                "instructions": _text(soul, 256_000, allow_empty=True),
                "isDefault": bool(record.get("is_default")),
                "hasAvatar": record.get("has_avatar") is True,
            }
            agents.append(agent)
        return {"agents": agents}

    async def agents_create(self, payload: dict[str, Any]) -> dict[str, Any]:
        draft = _agent_draft(payload)
        agent_id = _agent_id_from_name(draft["name"])
        await self._create_profile(
            agent_id=agent_id,
            display_name=draft["name"],
            description=draft["summary"],
            instructions=draft["instructions"],
        )
        if "avatar" in draft:
            await self._set_profile_avatar(agent_id, draft["avatar"])
        canonical_avatar = await self._profile_avatar(agent_id)
        return {
            "agent": {
                "id": agent_id,
                **draft,
                "isDefault": agent_id == "default",
                "hasAvatar": canonical_avatar.get("found") is True,
            }
        }

    async def agents_update(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if not {"agentId", "agent"}.issubset(values) or set(values) - {
            "agentId",
            "agent",
            "soulUpdate",
        }:
            raise WorkspaceControlError("Agent update payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        draft = _agent_draft({"agent": values.get("agent")})
        current_instructions = await self._profile_soul(agent_id)
        instructions: str | None = None
        expected_instructions_sha256: str | None = None
        if "soulUpdate" in values:
            soul_update = _object(values.get("soulUpdate"), "SOUL update")
            if set(soul_update) != {
                "confirmed",
                "expectedSha256",
                "instructions",
            } or soul_update.get("confirmed") is not True:
                raise WorkspaceControlError("SOUL update is not explicitly confirmed")
            expected_instructions_sha256 = _soul_digest_coordinate(
                soul_update.get("expectedSha256")
            )
            if not hmac.compare_digest(
                expected_instructions_sha256,
                _soul_digest(current_instructions),
            ):
                raise WorkspaceConflictError("SOUL changed before the update was confirmed")
            if not isinstance(soul_update.get("instructions"), str):
                raise WorkspaceControlError("SOUL update is invalid")
            instructions = _text(
                soul_update.get("instructions"),
                256_000,
                allow_empty=True,
            )
        await self._update_profile(
            agent_id=agent_id,
            display_name=draft["name"],
            description=draft["summary"],
            instructions=instructions,
            expected_instructions_sha256=expected_instructions_sha256,
        )
        if "avatar" in draft:
            await self._set_profile_avatar(agent_id, draft["avatar"])
        canonical_instructions = (
            instructions if instructions is not None else current_instructions
        )
        canonical_avatar = await self._profile_avatar(agent_id)
        return {
            "agent": {
                "id": agent_id,
                **draft,
                "instructions": canonical_instructions,
                "isDefault": agent_id == "default",
                "hasAvatar": canonical_avatar.get("found") is True,
            }
        }

    async def agents_avatar_get(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = _agent_payload_id(payload)
        avatar = await self._profile_avatar(agent_id)
        return {
            "agentId": agent_id,
            "avatar": (
                _agent_avatar_projection(avatar)
                if avatar.get("found") is True
                else None
            ),
        }

    async def agents_avatar_set(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "avatar"}:
            raise WorkspaceControlError("Agent avatar payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        avatar_value = values.get("avatar")
        avatar = None if avatar_value is None else _agent_avatar_payload(avatar_value)
        await self._set_profile_avatar(agent_id, avatar)
        return {"agentId": agent_id, "hasAvatar": avatar is not None}

    async def agent_defaults_get(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = _agent_payload_id(payload)
        config, options = await asyncio.gather(
            self._profile_config(agent_id),
            self._model_options(agent_id),
        )
        config = _object(config, "Hermes config")
        raw_model = config.get("model")
        model = _optional_object(raw_model)
        if isinstance(raw_model, str):
            # Hermes' normalized config exposes the selected model as a
            # string; its provider is authoritative in get_model_options().
            model = {
                "provider": options.get("provider"),
                "default": raw_model,
            }
        agent = _optional_object(config.get("agent"))
        delegation = _optional_object(config.get("delegation"))
        cron = _optional_object(config.get("cron"))
        platforms = _optional_object(config.get("platforms"))
        loopdy = _optional_object(platforms.get("loopdy"))
        extra = _optional_object(loopdy.get("extra"))
        agent_defaults = _optional_object(extra.get("agent_defaults"))
        scheduled = _optional_object(agent_defaults.get("scheduled_tasks"))
        defaults = {
            "mainChats": _selection(
                model.get("provider"),
                model.get("default"),
                agent.get("reasoning_effort"),
            ),
            "subagents": _selection(
                delegation.get("provider"),
                delegation.get("model"),
                delegation.get("reasoning_effort"),
            ),
            "scheduledTasks": _selection(
                cron.get("model_provider", cron.get("provider")),
                cron.get("model"),
                scheduled.get("reasoning_effort"),
            ),
        }
        return {
            "agentId": agent_id,
            "defaults": defaults,
            "providers": _provider_projection(options),
        }

    async def agent_defaults_set(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "defaults"}:
            raise WorkspaceControlError("Agent defaults payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        defaults = _defaults(values.get("defaults"))
        main = defaults["mainChats"]
        subagents = defaults["subagents"]
        scheduled = defaults["scheduledTasks"]
        config = {
            "model": {
                "provider": main["providerId"],
                "default": main["modelId"],
            },
            "agent": {"reasoning_effort": main["reasoningEffort"]},
            "delegation": {
                "provider": subagents["providerId"],
                "model": subagents["modelId"],
                "reasoning_effort": subagents["reasoningEffort"],
            },
            "cron": {
                "model_provider": scheduled["providerId"],
                "model": scheduled["modelId"],
            },
            "platforms": {
                "loopdy": {
                    "extra": {
                        "agent_defaults": {
                            "scheduled_tasks": {
                                "reasoning_effort": scheduled["reasoningEffort"]
                            }
                        }
                    }
                }
            },
        }
        await self._save_profile_config(agent_id, config)
        return {"agentId": agent_id, "defaults": defaults}

    async def skills_tools_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = _agent_payload_id(payload)
        raw_skills, raw_plugins, raw_mcp = await asyncio.gather(
            self._skills_catalog(agent_id),
            self._plugins_catalog(),
            self._mcp_catalog(agent_id),
        )
        if not isinstance(raw_skills, list) or len(raw_skills) > 1_000:
            raise WorkspaceControlError("Hermes skill catalog is invalid")
        if not isinstance(raw_plugins, list) or len(raw_plugins) > 256:
            raise WorkspaceControlError("Hermes plugin catalog is invalid")
        servers = _object(raw_mcp, "Hermes MCP catalog").get("servers")
        if not isinstance(servers, list) or len(servers) > 256:
            raise WorkspaceControlError("Hermes MCP catalog is invalid")

        skills: list[dict[str, Any]] = []
        for value in raw_skills:
            source = _object(value, "Hermes skill")
            name = _text(source.get("name"), 160)
            skills.append(
                {
                    "id": name,
                    "name": name,
                    "description": _text(
                        source.get("description"), 4_096, allow_empty=True
                    ),
                    "category": _text(
                        source.get("category"), 120, allow_empty=True
                    ),
                    "enabled": source.get("enabled") is not False,
                }
            )

        plugins: list[dict[str, Any]] = []
        for value in raw_plugins:
            source = _object(value, "Hermes plugin")
            counts = [
                _nonnegative_integer(source.get(key, 0), maximum=100_000)
                for key in ("tools", "hooks", "middleware", "commands")
            ]
            plugin_id = _text(source.get("key", source.get("name")), 160)
            plugins.append(
                {
                    "id": plugin_id,
                    "name": _text(source.get("name", plugin_id), 160),
                    "kind": _text(source.get("kind"), 80, allow_empty=True),
                    "version": _text(source.get("version"), 80, allow_empty=True),
                    "description": _text(
                        source.get("description"), 4_096, allow_empty=True
                    ),
                    "enabled": source.get("enabled") is not False,
                    "capabilityCount": sum(counts),
                }
            )

        mcp_servers: list[dict[str, Any]] = []
        for value in servers:
            source = _object(value, "Hermes MCP server")
            name = _text(source.get("name"), 160)
            tools = source.get("tools")
            tool_count = None
            if isinstance(tools, list):
                if len(tools) > 10_000:
                    raise WorkspaceControlError("Hermes MCP tool catalog is invalid")
                tool_count = len(tools)
            elif tools is not None and not isinstance(tools, dict):
                raise WorkspaceControlError("Hermes MCP tool catalog is invalid")
            mcp_servers.append(
                {
                    "id": name,
                    "name": name,
                    "transport": _text(
                        source.get("transport", "unknown"), 32
                    ),
                    "enabled": source.get("enabled") is not False,
                    "toolCount": tool_count,
                }
            )
        return {
            "agentId": agent_id,
            "skills": skills,
            "plugins": plugins,
            "mcpServers": mcp_servers,
        }

    async def projects_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) not in ({"agentId"}, {"agentId", "sessionId"}):
            raise WorkspaceControlError("Project list payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        session_id = _optional_coordinate(values.get("sessionId"), 128)
        projection = await self._project_projection(agent_id)
        if session_id is None:
            return projection

        getter = self.session_workspace_getter
        if not callable(getter):
            raise WorkspaceControlError("Workspace session anchoring is unavailable")
        session_root = getter(agent_id, session_id)
        if inspect.isawaitable(session_root):
            session_root = await session_root
        if session_root in (None, ""):
            projection["sessionWorkspaceId"] = None
            return projection

        canonical_root = _absolute_project_path(session_root)
        raw_catalog = _object(
            await self._projects_catalog(agent_id), "Hermes project catalog"
        )
        rows = raw_catalog.get("projects")
        if not isinstance(rows, list) or len(rows) > 256:
            raise WorkspaceControlError("Hermes project catalog is invalid")
        matches = [
            _coordinate(project.get("id"), 160)
            for project in rows
            if isinstance(project, dict)
            and project.get("archived") is not True
            and _project_primary_path(project) == canonical_root
        ]
        if len(matches) > 1:
            raise WorkspaceControlError("Workspace session anchoring is ambiguous")
        projection["sessionWorkspaceId"] = matches[0] if matches else None
        return projection

    async def projects_set_active(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) not in (
            {"agentId", "workspaceId"},
            {"agentId", "workspaceId", "sessionId"},
        ):
            raise WorkspaceControlError("Workspace selection payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        workspace_id = _coordinate(values.get("workspaceId"), 160)
        session_id = _optional_coordinate(values.get("sessionId"), 128)
        catalog = await self._project_projection(agent_id)
        if not any(row["id"] == workspace_id for row in catalog["workspaces"]):
            raise WorkspaceControlError("Workspace is unavailable")
        if session_id is not None:
            setter = self.session_workspace_setter
            primary_path = await self._project_directory(agent_id, workspace_id)
            if not callable(setter) or not primary_path:
                raise WorkspaceControlError("Workspace session anchoring is unavailable")
            result = setter(agent_id, session_id, primary_path)
            if inspect.isawaitable(result):
                await result
        await self._set_active_project(agent_id, workspace_id)
        return await self._project_projection(agent_id)

    async def projects_create(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "name", "folderPath"}:
            raise WorkspaceControlError("Workspace creation payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        name = _text(values.get("name"), 160)
        folder_path = _canonical_project_directory(values.get("folderPath"))
        await self._create_project(agent_id, name, folder_path)
        return await self._project_projection(agent_id)

    async def projects_archive(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "workspaceId"}:
            raise WorkspaceControlError("Workspace archive payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        workspace_id = _coordinate(values.get("workspaceId"), 160)
        await self._archive_project(agent_id, workspace_id)
        return await self._project_projection(agent_id)

    async def projects_list_directory(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "parentPath", "prefix", "offset", "limit"}:
            raise WorkspaceControlError("Workspace directory payload is invalid")
        _agent_id(values.get("agentId"))
        parent_path = _canonical_project_directory(values.get("parentPath"))
        prefix = _project_directory_prefix(values.get("prefix"))
        offset = _nonnegative_integer(
            values.get("offset"), maximum=_PROJECT_DIRECTORY_OFFSET_LIMIT
        )
        limit = _nonnegative_integer(
            values.get("limit"), maximum=_PROJECT_DIRECTORY_PAGE_LIMIT
        )
        if limit == 0:
            raise WorkspaceControlError("Workspace directory page is invalid")
        return await asyncio.to_thread(
            _project_directory_page,
            parent_path,
            prefix,
            offset,
            limit,
        )

    async def projects_git_capabilities(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        context = await self._project_git_context(
            payload, {"agentId", "sessionId", "workspaceId"}
        )
        try:
            raw = await asyncio.to_thread(context["service"].capabilities)
        except WorkspaceGitError as exc:
            raise _project_git_control_error(exc) from exc
        value = _object(raw, "Project Git capabilities")
        rows = value.get("workspaces")
        if not isinstance(rows, list):
            raise WorkspaceControlError("Project Git capability response is invalid")
        selected = [
            row
            for row in rows
            if isinstance(row, dict)
            and row.get("workspace_id") == context["workspace_id"]
        ]
        if len(selected) != 1:
            raise WorkspaceControlError("Project Git is unavailable for this Project")
        selected_operations = selected[0].get("operations")
        if not isinstance(selected_operations, list):
            raise WorkspaceControlError("Project Git capability response is invalid")
        enabled = set(selected_operations)
        mutations_enabled = selected[0].get("mutations_enabled") is True
        return _project_git_wire(
            {
                "schema_version": value.get("schema_version"),
                "capabilities": {
                    "status": "status" in enabled,
                    "stage": mutations_enabled and "stage" in enabled,
                    "commit": mutations_enabled and "commit" in enabled,
                    "push": mutations_enabled and "push" in enabled,
                    "fetch": mutations_enabled and "fetch" in enabled,
                    "pull": mutations_enabled and "pull" in enabled,
                    "arbitrary_command": False,
                },
                "workspaces": selected,
            }
        )

    async def projects_git_status(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = await self._project_git_context(
            payload, {"agentId", "sessionId", "workspaceId"}
        )
        try:
            raw = await asyncio.to_thread(
                context["service"].status, context["workspace_id"]
            )
        except WorkspaceGitError as exc:
            raise _project_git_control_error(exc) from exc
        return _project_git_wire(_object(raw, "Project Git status"))

    async def projects_git_diff(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = await self._project_git_context(
            payload,
            {
                "agentId",
                "sessionId",
                "workspaceId",
                "path",
                "side",
                "statusToken",
                "offset",
                "limit",
            },
        )
        path = _project_git_relative_path(context["values"].get("path"))
        side = _project_git_choice(
            context["values"].get("side"), {"staged", "worktree"}
        )
        status_token = _project_git_status_token(
            context["values"].get("statusToken")
        )
        offset = _nonnegative_integer(
            context["values"].get("offset"), maximum=100_000
        )
        limit = _nonnegative_integer(
            context["values"].get("limit"), maximum=500
        )
        if limit < 1:
            raise WorkspaceControlError("Project Git diff page is invalid")
        try:
            raw = await asyncio.to_thread(
                context["service"].diff,
                context["workspace_id"],
                path=path,
                side=side,
                expected_status_token=status_token,
                offset=offset,
                limit=limit,
            )
        except WorkspaceGitError as exc:
            raise _project_git_control_error(exc) from exc
        return _project_git_wire(_object(raw, "Project Git diff"))

    async def projects_git_prepare(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = await self._project_git_context(
            payload,
            {
                "agentId",
                "sessionId",
                "workspaceId",
                "operation",
                "statusToken",
                "input",
            },
        )
        operation = _project_git_choice(
            context["values"].get("operation"),
            {"stage", "commit", "fetch", "pull", "push"},
        )
        input_ = _project_git_operation_input(
            operation, context["values"].get("input")
        )
        connection_id = self._project_git_connection_id()
        try:
            raw = await asyncio.to_thread(
                context["service"].prepare,
                workspace_id=context["workspace_id"],
                operation=operation,
                input_=input_,
                expected_status_token=_project_git_status_token(
                    context["values"].get("statusToken")
                ),
                connection_id=connection_id,
            )
        except WorkspaceGitError as exc:
            raise _project_git_control_error(exc) from exc
        return _project_git_wire(_object(raw, "Project Git preparation"))

    async def projects_git_execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = await self._project_git_context(
            payload,
            {
                "agentId",
                "sessionId",
                "workspaceId",
                "operation",
                "statusToken",
                "input",
                "confirmationToken",
                "idempotencyKey",
            },
        )
        operation = _project_git_choice(
            context["values"].get("operation"),
            {"stage", "commit", "fetch", "pull", "push"},
        )
        input_ = _project_git_operation_input(
            operation, context["values"].get("input")
        )
        confirmation_token = _coordinate(
            context["values"].get("confirmationToken"), 200
        )
        idempotency_key = context["values"].get("idempotencyKey")
        if not isinstance(idempotency_key, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            idempotency_key,
        ):
            raise WorkspaceControlError("Project Git idempotency key is invalid")
        request = {
            "workspace_id": context["workspace_id"],
            "expected_status_token": _project_git_status_token(
                context["values"].get("statusToken")
            ),
            "confirmation_token": confirmation_token,
            "idempotency_key": idempotency_key,
            **input_,
        }
        try:
            raw = await asyncio.to_thread(
                context["service"].execute,
                operation,
                request,
                connection_id=self._project_git_connection_id(),
            )
        except WorkspaceGitError as exc:
            raise _project_git_control_error(exc) from exc
        return _project_git_wire(_object(raw, "Project Git execution"))

    async def _project_git_context(
        self,
        payload: dict[str, Any],
        expected_keys: set[str],
    ) -> dict[str, Any]:
        values = _object(payload, "Project Git payload")
        if set(values) != expected_keys:
            raise WorkspaceControlError("Project Git payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        session_id = _coordinate(values.get("sessionId"), 128)
        workspace_id = _coordinate(values.get("workspaceId"), 160)
        raw_catalog = _object(
            await self._projects_catalog(agent_id), "Hermes project catalog"
        )
        projects = raw_catalog.get("projects")
        if not isinstance(projects, list) or len(projects) > 256:
            raise WorkspaceControlError("Hermes project catalog is invalid")
        matches = [
            _object(row, "Hermes project")
            for row in projects
            if isinstance(row, dict)
            and row.get("id") == workspace_id
            and row.get("archived") is not True
        ]
        if len(matches) != 1:
            raise WorkspaceControlError("Project Git Project is unavailable")
        project = matches[0]
        project_root = _project_primary_path(project)
        getter = self.session_workspace_getter
        if not callable(getter):
            raise WorkspaceControlError("Project Git session ownership is unavailable")
        session_root = getter(agent_id, session_id)
        if inspect.isawaitable(session_root):
            session_root = await session_root
        if not _same_project_path(session_root, project_root):
            raise WorkspaceControlError("The session is not anchored to this Project")
        try:
            service = self.workspace_git or self._project_git_service(
                agent_id, workspace_id, project, project_root
            )
        except WorkspaceGitError as exc:
            raise _project_git_control_error(exc) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkspaceControlError(
                "Git is unavailable for this Project.",
                code="git_unavailable",
            ) from exc
        return {
            "values": values,
            "agent_id": agent_id,
            "session_id": session_id,
            "workspace_id": workspace_id,
            "service": service,
        }

    def _project_git_connection_id(self) -> str:
        getter = self.connection_id_getter
        value = getter() if callable(getter) else None
        if inspect.isawaitable(value):
            raise WorkspaceControlError("Project Git connection identity is unavailable")
        return _coordinate(value, 200)

    def _project_git_service(
        self,
        agent_id: str,
        workspace_id: str,
        project: dict[str, Any],
        project_root: str,
    ) -> WorkspaceGitService:
        policy = _project_git_policy(workspace_id, project_root)
        policy_digest = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        key = (agent_id, workspace_id, project_root, policy_digest)
        cached = self._project_git_services.get(key)
        if cached is not None:
            self._project_git_services.move_to_end(key)
            return cached
        service = WorkspaceGitService(
            [
                {
                    "workspace_id": workspace_id,
                    "label": _text(project.get("name"), 120),
                    "root": project_root,
                    **policy,
                }
            ],
            state_path=self.workspace_git_state_path,
        )
        self._project_git_services[key] = service
        while len(self._project_git_services) > 256:
            self._project_git_services.popitem(last=False)
        return service

    async def _project_projection(self, agent_id: str) -> dict[str, Any]:
        raw = _object(
            await self._projects_catalog(agent_id),
            "Hermes project catalog",
        )
        active_id = _optional_coordinate(raw.get("active_id"), 160)
        rows = raw.get("projects")
        if not isinstance(rows, list) or len(rows) > 256:
            raise WorkspaceControlError("Hermes project catalog is invalid")
        workspaces: list[dict[str, Any]] = []
        seen: set[str] = set()
        for value in rows:
            source = _object(value, "Hermes project")
            if source.get("archived") is True:
                continue
            workspace_id = _coordinate(source.get("id"), 160)
            if workspace_id in seen:
                raise WorkspaceControlError("Hermes project catalog is ambiguous")
            seen.add(workspace_id)
            folders = source.get("folders", [])
            if not isinstance(folders, list) or len(folders) > 10_000:
                raise WorkspaceControlError("Hermes project folder catalog is invalid")
            workspaces.append(
                {
                    "id": workspace_id,
                    "name": _text(source.get("name"), 160),
                    "description": _text(
                        source.get("description"), 4_096, allow_empty=True
                    ),
                    "folderCount": len(folders),
                    "isActive": workspace_id == active_id,
                }
            )
        if active_id is not None and active_id not in seen:
            active_id = None
        return {"activeWorkspaceId": active_id, "workspaces": workspaces}

    async def sessions_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) - {"agentId"}:
            raise WorkspaceControlError("Session list payload is invalid")
        agent_id = _agent_id(values["agentId"]) if "agentId" in values else None
        raw = _object(await self._session_catalog(agent_id), "Hermes session catalog")
        rows = raw.get("sessions")
        if not isinstance(rows, list) or len(rows) > 500:
            raise WorkspaceControlError("Hermes session catalog is invalid")
        sources = [_object(row, "Hermes session") for row in rows]
        sources.sort(
            key=lambda source: (
                _timestamp(source.get("last_active", source.get("started_at"))),
                _timestamp(source.get("started_at")),
                _coordinate(source.get("id"), 160),
            ),
            reverse=True,
        )
        sessions = []
        stored_ids: set[str] = set()
        for source in sources:
            stored_id = _coordinate(source.get("id"), 160)
            if stored_id in stored_ids:
                raise WorkspaceControlError("Hermes session coordinates are ambiguous")
            stored_ids.add(stored_id)
        visible_ids: set[str] = set()
        for source in sources:
            stored_id = _coordinate(source.get("id"), 160)
            profile = _agent_id(source.get("profile"))
            session_source = _coordinate(source.get("source", "local"), 64)
            chat_id = _optional_coordinate(source.get("chat_id"), 160)
            preferred_visible_id = (
                chat_id if session_source == "loopdy" and chat_id else stored_id
            )
            # A model/reset boundary can create a second durable Hermes row
            # for the same Loopdy chat id. They are distinct transcripts and
            # must both remain resumable. The catalog is ordered newest-first,
            # so the current row keeps the stable chat alias and older rows use
            # their exact durable id. Never let an alias occupy another row's
            # durable coordinate.
            visible_id = (
                preferred_visible_id
                if preferred_visible_id not in visible_ids
                and (
                    preferred_visible_id == stored_id
                    or preferred_visible_id not in stored_ids
                )
                else stored_id
            )
            if visible_id in visible_ids:
                raise WorkspaceControlError("Hermes session coordinates are ambiguous")
            visible_ids.add(visible_id)
            is_active = source.get("is_active") is True
            if session_source == "loopdy" and callable(self.session_active_getter):
                resolved_active = self.session_active_getter(
                    profile,
                    preferred_visible_id,
                    stored_id,
                )
                if inspect.isawaitable(resolved_active):
                    resolved_active = await resolved_active
                is_active = resolved_active is True
            sessions.append(
                {
                    "storedId": stored_id,
                    "profile": profile,
                    "source": session_source,
                    "chatId": chat_id,
                    "visibleId": visible_id,
                    "title": _text(
                        source.get("title", "Hermes session"), 240, allow_empty=True
                    )
                    or "Hermes session",
                    "preview": _text(source.get("preview"), 4_096, allow_empty=True),
                    "messageCount": _nonnegative_integer(
                        source.get("message_count", 0), maximum=10_000_000
                    ),
                    "startedAt": _timestamp(source.get("started_at")),
                    "lastActive": _timestamp(
                        source.get("last_active", source.get("started_at"))
                    ),
                    "isActive": is_active,
                }
            )
        return {"sessions": sessions}

    async def sessions_history(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        required = {"storedId", "agentId"}
        if not required.issubset(values) or set(values) - required - {"offset", "turnLimit"}:
            raise WorkspaceControlError("Session history payload is invalid")
        stored_id = _coordinate(values.get("storedId"), 160)
        agent_id = _agent_id(values.get("agentId"))
        offset = _nonnegative_integer(
            values.get("offset", 0),
            maximum=_SESSION_HISTORY_OFFSET_LIMIT,
        )
        turn_limit = None
        if "turnLimit" in values:
            turn_limit = _nonnegative_integer(values["turnLimit"], maximum=10)
            if turn_limit < 1:
                raise WorkspaceControlError("Session history turn limit is invalid")
        history_options: dict[str, Any] = {"include_compacted": True}
        if "offset" in values:
            history_options["offset"] = offset
        try:
            raw = _object(
                await self._session_messages(
                    stored_id,
                    agent_id,
                    **history_options,
                ),
                "Hermes session history",
            )
        except Exception as exc:
            # Loopdy shows chat_id as its stable visible coordinate, while
            # Hermes' history endpoint resolves the stored session id. Use
            # the official, profile-scoped catalog to bridge that alias on
            # reopen; never infer an id from transcript text or a prefix.
            if getattr(exc, "status_code", None) != 404:
                raise
            catalog = _object(
                await self._session_catalog(agent_id),
                "Hermes session catalog",
            )
            resolved = _stored_session_id_for_visible(catalog, stored_id)
            if resolved is None:
                raise
            stored_id = resolved
            raw = _object(
                await self._session_messages(
                    stored_id,
                    agent_id,
                    **history_options,
                ),
                "Hermes session history",
            )
        rows = raw.get("messages")
        if not isinstance(rows, list) or len(rows) > 500:
            raise WorkspaceControlError("Hermes session history is invalid")
        messages_by_row: dict[int, dict[str, Any]] = {}
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            role = row.get("role")
            if not isinstance(role, str) or role not in _HISTORY_ROLES:
                continue
            # Hermes includes a display_content field on every row, but it is
            # intentionally null for compacted rows that still carry their
            # user-visible text in content. Prefer the display projection
            # when it is non-empty and fall back to the persisted content
            # otherwise. Hermes can send an empty display projection for a
            # row that still has user-visible text in content.
            display_content = row.get("display_content")
            content = (
                display_content
                if isinstance(display_content, str) and display_content != ""
                else row.get("content")
            )
            if not isinstance(content, str) or len(content.encode("utf-8")) > 1_000_000:
                continue
            raw_id = row.get("id", index + 1)
            message_id = (
                str(raw_id)
                if isinstance(raw_id, int) and not isinstance(raw_id, bool)
                else _coordinate(raw_id, 128)
            )
            message: dict[str, Any] = {
                "id": message_id,
                "role": role,
                "content": content,
            }
            if isinstance(raw_id, int) and not isinstance(raw_id, bool):
                # The mobile projection uses the numeric row coordinate to
                # reconcile history with live events and tool results.
                message["row_id"] = raw_id
            for field in _HISTORY_RICH_FIELDS:
                value = row.get(field)
                if value is None:
                    continue
                if isinstance(value, str) and len(value.encode("utf-8")) > 256_000:
                    value = _utf8_prefix(value, 256_000)
                try:
                    message[field] = _workspace_json(value, depth=0)
                except (TypeError, ValueError):
                    # A malformed optional rich field must not hide the
                    # otherwise renderable user/assistant/tool record.
                    continue
            messages_by_row[index] = message

        selected: list[dict[str, Any]] = []
        consumed = 0
        selected_turns = 0
        for index in range(len(rows) - 1, -1, -1):
            message = messages_by_row.get(index)
            if message is None:
                consumed += 1
                continue
            candidate = [message, *selected]
            candidate_response = {
                "storedId": stored_id,
                "agentId": agent_id,
                "messages": candidate,
                "nextOffset": offset + consumed + 1,
            }
            encoded = json.dumps(
                candidate_response,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(encoded) > _SESSION_HISTORY_RESPONSE_MAX_BYTES:
                if not selected:
                    consumed += 1
                    continue
                break
            selected = candidate
            consumed += 1
            if message["role"] == "user":
                selected_turns += 1
                if turn_limit is not None and selected_turns >= turn_limit:
                    break

        result = {
            "storedId": stored_id,
            "agentId": agent_id,
            "messages": selected,
        }
        if consumed < len(rows) or len(rows) == 500:
            result["nextOffset"] = offset + consumed
        return result

    async def attachments_resolve(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "storedId", "items"}:
            raise WorkspaceControlError("Attachment resolve payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        stored_id = _coordinate(values.get("storedId"), 160)
        raw_items = values.get("items")
        if not isinstance(raw_items, list) or not 1 <= len(raw_items) <= 200:
            raise WorkspaceControlError("Attachment resolve payload is invalid")
        items: list[dict[str, str]] = []
        for value in raw_items:
            item = _object(value, "attachment item")
            if set(item) != {"itemId", "text"}:
                raise WorkspaceControlError("Attachment resolve payload is invalid")
            text = item.get("text")
            if not isinstance(text, str) or len(text.encode("utf-8")) > 100_000:
                raise WorkspaceControlError("Attachment resolve payload is invalid")
            items.append({"id": _coordinate(item.get("itemId"), 200), "text": text})
        resolved = await asyncio.to_thread(
            self.attachment_store.resolve,
            profile=agent_id,
            session_id=stored_id,
            items=items,
        )
        projected = []
        for item in resolved:
            attachments = [
                {
                    "id": attachment["id"],
                    "fileName": attachment["name"],
                    "mimeType": attachment["mime_type"],
                    "byteCount": attachment["size"],
                }
                for attachment in item["attachments"]
                if 0 < attachment["size"] <= MAX_ATTACHMENT_BYTES
            ]
            projected.append({
                "itemId": item["id"],
                "text": item["text"],
                "attachments": attachments,
            })
        return {"items": projected}

    async def attachments_fetch(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"agentId", "attachmentId", "offset"}:
            raise WorkspaceControlError("Attachment fetch payload is invalid")
        agent_id = _agent_id(values.get("agentId"))
        attachment_id = _coordinate(values.get("attachmentId"), 128)
        offset = _nonnegative_integer(values.get("offset"), maximum=MAX_ATTACHMENT_BYTES)
        attachment = await asyncio.to_thread(
            self.attachment_store.read,
            profile=agent_id,
            attachment_id=attachment_id,
        )
        if attachment is None or not 0 < attachment["size"] <= MAX_ATTACHMENT_BYTES:
            raise WorkspaceControlError("Attachment is unavailable")
        content = attachment["content"]
        if not isinstance(content, bytes) or len(content) != attachment["size"] or offset >= len(content):
            raise WorkspaceControlError("Attachment is unavailable")
        chunk = content[offset : offset + MAX_ATTACHMENT_CHUNK_BYTES]
        next_offset = offset + len(chunk)
        return {
            "attachmentId": attachment_id,
            "offset": offset,
            "data": base64.b64encode(chunk).decode("ascii"),
            "nextOffset": next_offset if next_offset < len(content) else None,
        }

    async def scheduled_tasks_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) - {"agentId"}:
            raise WorkspaceControlError("Scheduled task list payload is invalid")
        agent_id = _agent_id(values["agentId"]) if "agentId" in values else None
        rows = await self._cron_list(agent_id)
        if not isinstance(rows, list) or len(rows) > 500:
            raise WorkspaceControlError("Hermes scheduled task catalog is invalid")
        return {
            "tasks": [
                _task_projection(row, default_agent_id=agent_id)
                for row in rows
            ]
        }

    async def scheduled_tasks_delivery_targets(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        _empty_payload(payload)
        return {"targets": _delivery_target_catalog(await self._cron_delivery_targets())}

    async def scheduled_tasks_create(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _scheduled_task_draft(payload)
        agent_id = values.pop("agentId")
        delivery = _scheduled_task_delivery(
            values.pop("delivery"),
            await self._cron_delivery_targets(),
        )
        config = _object(await self._profile_config(agent_id), "Hermes config")
        cron = _optional_object(config.get("cron"))
        platforms = _optional_object(config.get("platforms"))
        loopdy = _optional_object(platforms.get("loopdy"))
        extra = _optional_object(loopdy.get("extra"))
        agent_defaults = _optional_object(extra.get("agent_defaults"))
        scheduled = _optional_object(agent_defaults.get("scheduled_tasks"))
        provider = _identifier(
            cron.get("model_provider", cron.get("provider")), 128
        )
        model = _identifier(cron.get("model"), 256)
        reasoning = _reasoning(scheduled.get("reasoning_effort"))
        create = {
            "name": values["name"],
            "prompt": values["instructions"],
            "schedule": values["schedule"],
            "deliver": delivery,
        }
        if provider:
            create["provider"] = provider
        if model:
            create["model"] = model
        job = await self._cron_create(agent_id, create)
        task = _task_projection(job, default_agent_id=agent_id)
        if reasoning:
            job = await self._cron_update(
                task["id"], agent_id, {"reasoning_effort": reasoning}
            )
            task = _task_projection(job, default_agent_id=agent_id)
        return {"task": task}

    async def scheduled_tasks_update(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"taskId", "agentId", "changes"}:
            raise WorkspaceControlError("Scheduled task update payload is invalid")
        task_id = _coordinate(values.get("taskId"), 160)
        agent_id = _agent_id(values.get("agentId"))
        changes = _object(values.get("changes"), "scheduled task changes")
        if set(changes) != {"name", "instructions", "schedule", "delivery"}:
            raise WorkspaceControlError("Scheduled task changes are invalid")
        updates = {
            "name": _text(changes.get("name"), 240),
            "prompt": _text(changes.get("instructions"), 256_000),
            "schedule": _text(changes.get("schedule"), 2_048),
            "deliver": _scheduled_task_delivery(
                changes.get("delivery"),
                await self._cron_delivery_targets(),
            ),
        }
        job = await self._cron_update(task_id, agent_id, updates)
        return {"task": _task_projection(job, default_agent_id=agent_id)}

    async def scheduled_tasks_pause(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._scheduled_task_action(payload, self._cron_pause)

    async def scheduled_tasks_resume(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._scheduled_task_action(payload, self._cron_resume)

    async def scheduled_tasks_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._scheduled_task_action(payload, self._cron_run)

    async def scheduled_tasks_delete(self, payload: dict[str, Any]) -> dict[str, Any]:
        task_id, agent_id = _task_coordinate(payload)
        await self._cron_delete(task_id, agent_id)
        return {"taskId": task_id, "deleted": True}

    async def dashboard_load(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload == {}:
            schema_version = 1
        elif (
            isinstance(payload, dict)
            and set(payload) == {"schemaVersion"}
            and type(payload.get("schemaVersion")) is int
            and payload["schemaVersion"] == 2
        ):
            schema_version = 2
        else:
            raise WorkspaceControlError("Dashboard payload is invalid")
        await asyncio.to_thread(self._clean_dashboard_events)
        if schema_version == 1:
            events = await asyncio.to_thread(self._dashboard_events)
            return {"events": events}
        events = await self._dashboard_events_v2()
        return {"schemaVersion": 2, "events": events}

    async def dashboard_set_event_state(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"eventId", "isRead", "isPinned"}:
            raise WorkspaceControlError("Dashboard event state payload is invalid")
        event_id = _coordinate(values.get("eventId"), 220)
        is_read = values.get("isRead")
        is_pinned = values.get("isPinned")
        if type(is_read) is not bool or type(is_pinned) is not bool:
            raise WorkspaceControlError("Dashboard event state payload is invalid")
        changed = await asyncio.to_thread(
            self.service.store.set_event_state,
            event_id,
            is_read=is_read,
            is_pinned=is_pinned,
        )
        if not changed:
            raise WorkspaceConflictError("Dashboard event is no longer available")
        return {"eventId": event_id, "isRead": is_read, "isPinned": is_pinned}

    async def dashboard_dismiss_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"eventId"}:
            raise WorkspaceControlError("Dashboard event payload is invalid")
        event_id = _coordinate(values.get("eventId"), 220)
        dismissed = await asyncio.to_thread(self.service.store.dismiss_event, event_id)
        if not dismissed:
            raise WorkspaceConflictError("Dashboard event is no longer available")
        return {"eventId": event_id, "dismissed": True}

    async def dashboard_dismiss_events(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if values == {"all": True}:
            rows = await asyncio.to_thread(self._all_events)
            ids = [_coordinate(row.get("event_id"), 220) for row in rows]
            return {"dismissed": await self._dismiss_event_ids(ids)}
        allowed = {"eventIds", "eventTypes", "createdBefore"}
        if not values or set(values) - allowed:
            raise WorkspaceControlError("Dashboard dismissal payload is invalid")
        has_ids = "eventIds" in values
        has_types = "eventTypes" in values
        if has_ids == has_types:
            raise WorkspaceControlError("Choose event IDs or event types")
        cutoff = (
            _timestamp(values.get("createdBefore"))
            if "createdBefore" in values
            else None
        )
        if has_ids:
            ids = _coordinate_list(values.get("eventIds"), maximum=2_000, item_maximum=220)
            return {"dismissed": await self._dismiss_event_ids(ids, created_before=cutoff)}
        event_types = _coordinate_list(
            values.get("eventTypes"), maximum=32, item_maximum=80
        )
        dismissed = await asyncio.to_thread(
            self.service.store.dismiss_events,
            event_types=event_types,
            created_before=cutoff,
        )
        return {"dismissed": _nonnegative_integer(dismissed, maximum=10_000_000)}

    async def approvals_load(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"approvalId"}:
            raise WorkspaceControlError("Approval payload is invalid")
        approval_id = _coordinate(values.get("approvalId"), 180)
        approval = await asyncio.to_thread(self.service.store.get_approval, approval_id)
        projected = _approval_projection(approval, now=int(self.clock()))
        event = await asyncio.to_thread(
            self.service.store.get_event, projected["eventId"]
        )
        projected_event = _event_projection(event)
        if (
            projected_event["type"] != "approval.required"
            or projected_event["approvalId"] != approval_id
        ):
            raise WorkspaceConflictError("Approval event changed")
        return {"approval": projected, "event": projected_event}

    async def approvals_respond(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"approvalId", "requestDigest", "choice"}:
            raise WorkspaceControlError("Approval response payload is invalid")
        approval_id = _coordinate(values.get("approvalId"), 180)
        digest = _coordinate(values.get("requestDigest"), 180)
        choice = _coordinate(values.get("choice"), 16)
        if choice not in {"once", "session", "always", "deny"}:
            raise WorkspaceControlError("Approval choice is invalid")
        approval = await asyncio.to_thread(self.service.store.get_approval, approval_id)
        projected = _approval_projection(approval, now=int(self.clock()))
        if projected["requestDigest"] != digest or choice not in projected["allowedChoices"]:
            raise WorkspaceConflictError("Approval request changed")
        accepted = await asyncio.to_thread(
            self.service.store.respond_approval, approval_id, choice
        )
        if not accepted:
            raise WorkspaceConflictError("Approval is expired or already answered")
        return {"accepted": True, "approvalId": approval_id, "choice": choice}

    async def clarifications_respond(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = _object(payload, "workspace payload")
        if set(values) != {"eventId", "clarifyId", "response"}:
            raise WorkspaceControlError("Clarification response payload is invalid")
        event_id = _coordinate(values.get("eventId"), 220)
        clarify_id = _coordinate(values.get("clarifyId"), 180)
        response = _text(values.get("response"), 16_000)
        if not response:
            raise WorkspaceControlError("Clarification response is invalid")

        event = await asyncio.to_thread(self.service.store.get_event, event_id)
        source = _object(event, "Loopdy clarification event")
        detail = _object(source.get("detail"), "Loopdy clarification detail")
        if (
            source.get("dismissed_at") is not None
            or source.get("type") != "attention.required"
            or detail.get("kind") != "clarify"
            or detail.get("request_id") != clarify_id
        ):
            raise WorkspaceConflictError("Clarification request changed")
        try:
            interaction = _clarify_interaction_projection(detail.get("interaction"))
        except (TypeError, ValueError, WorkspaceControlError) as error:
            raise WorkspaceConflictError("Clarification request changed") from error
        if interaction["requestId"] != clarify_id:
            raise WorkspaceConflictError("Clarification request changed")
        session_key = _coordinate(
            detail.get("session_key") or source.get("session_id"),
            180,
        )
        raw_expiry = detail.get("expires_at")
        scalar_expiry = _timestamp(raw_expiry) if raw_expiry is not None else None
        if scalar_expiry != interaction["expiresAt"]:
            raise WorkspaceConflictError("Clarification request changed")
        if scalar_expiry is not None and scalar_expiry <= int(self.clock()):
            raise WorkspaceConflictError("Clarification request expired")

        from tools.clarify_gateway import (
            get_pending_for_session,
            resolve_gateway_clarify,
        )

        pending = await asyncio.to_thread(
            get_pending_for_session,
            session_key,
            include_choice_prompts=True,
        )
        if (
            pending is None
            or str(getattr(pending, "clarify_id", "")) != clarify_id
        ):
            raise WorkspaceConflictError("Clarification is no longer pending")
        accepted = await asyncio.to_thread(
            resolve_gateway_clarify,
            clarify_id,
            response,
        )
        if not accepted:
            raise WorkspaceConflictError("Clarification is no longer pending")
        await asyncio.to_thread(self.service.store.dismiss_event, event_id)
        return {
            "accepted": True,
            "eventId": event_id,
            "clarifyId": clarify_id,
        }

    def _clean_dashboard_events(self) -> None:
        now = int(self.clock())
        store = self.service.store
        store.dismiss_gateway_lifecycle_events(dismissed_at=now)
        store.dismiss_inactive_approval_events(now=now, dismissed_at=now)
        try:
            if self.clarify_timeout is not None:
                clarify_timeout = int(self.clarify_timeout())
            else:
                from tools.clarify_gateway import get_clarify_timeout

                clarify_timeout = int(get_clarify_timeout())
        except (ImportError, TypeError, ValueError):
            clarify_timeout = 3_600
        if clarify_timeout > 0:
            store.dismiss_expired_attention(
                now - clarify_timeout,
                dismissed_at=now,
            )

    def _all_events(self, *, maximum: int = 2_000) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        offset = 0
        while offset < maximum:
            page_limit = min(200, maximum - offset)
            page = self.service.store.list_events(limit=page_limit, offset=offset)
            if not isinstance(page, list) or len(page) > 200:
                raise WorkspaceControlError("Loopdy event catalog is invalid")
            events.extend(page)
            if len(page) < page_limit:
                break
            offset += len(page)
        return events

    def _dashboard_events(self) -> list[dict[str, Any]]:
        """Return a recent, transport-sized event projection source.

        A dashboard response is sent in one encrypted Loopdy Link frame. A
        full event catalog can exceed that frame even though each individual
        event is valid, so keep this summary bounded and let session history
        provide the complete detail path.
        """
        rows = self._all_events(maximum=_DASHBOARD_EVENT_LIMIT)
        selected: list[dict[str, Any]] = []
        for row in rows:
            projected = _event_projection(
                row,
                detail_maximum=_DASHBOARD_DETAIL_MAX_BYTES,
                truncate_detail=True,
            )
            candidate = selected + [projected]
            encoded = json.dumps(
                {"events": candidate},
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            if len(encoded) > _DASHBOARD_RESPONSE_MAX_BYTES:
                break
            selected.append(projected)
        return selected

    async def _dashboard_events_v2(self) -> list[dict[str, Any]]:
        rows = await asyncio.to_thread(
            self._all_events,
            maximum=_DASHBOARD_EVENT_LIMIT,
        )
        enriched = await self.enrich_completion_events(
            rows,
            preserve_unenriched=False,
        )
        selected: list[dict[str, Any]] = []
        for row in enriched:
            try:
                projected = _event_projection_v2(
                    row,
                    detail_maximum=_DASHBOARD_DETAIL_MAX_BYTES,
                    truncate_detail=True,
                )
            except (TypeError, ValueError, WorkspaceControlError):
                if isinstance(row, dict) and row.get("type") in _COMPLETION_EVENT_TYPES:
                    continue
                raise
            candidate = selected + [projected]
            encoded = json.dumps(
                {"schemaVersion": 2, "events": candidate},
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            if len(encoded) > _DASHBOARD_RESPONSE_MAX_BYTES:
                break
            selected.append(projected)
        return selected

    async def enrich_completion_events(
        self,
        rows: list[dict[str, Any]],
        *,
        preserve_unenriched: bool = True,
    ) -> list[dict[str, Any]]:
        """Resolve completion metadata without dropping durable REST events."""
        if not isinstance(rows, list) or len(rows) > _DASHBOARD_EVENT_LIMIT:
            raise WorkspaceControlError("Loopdy event catalog is invalid")
        catalogs: dict[str, dict[str, str] | None] = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("type") not in _COMPLETION_EVENT_TYPES:
                continue
            try:
                profile = _agent_id(row.get("profile"))
            except (TypeError, ValueError, WorkspaceControlError):
                continue
            if profile in catalogs:
                continue
            try:
                catalogs[profile] = _completion_catalog(
                    await self._cron_list(profile),
                    profile=profile,
                )
            except Exception:
                catalogs[profile] = None

        enriched: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or row.get("type") not in _COMPLETION_EVENT_TYPES:
                enriched.append(row)
                continue
            try:
                profile = _agent_id(row.get("profile"))
                session_id = _coordinate(row.get("session_id"), 180)
                task_id = await self._canonical_cron_job_id(
                    session_id,
                    profile,
                )
                catalog = catalogs.get(profile)
                if catalog is None or task_id not in catalog:
                    if preserve_unenriched:
                        enriched.append(row)
                    continue
                history = _object(
                    await self._session_messages(
                        session_id,
                        profile,
                        include_compacted=True,
                    ),
                    "Hermes session history",
                )
                detail = dict(_optional_object(row.get("detail")))
                detail.update(
                    {
                        "title": catalog[task_id],
                        "summary": _final_assistant_result(history),
                        "status": (
                            "completed"
                            if row.get("type") == "job.completed"
                            else "failed"
                        ),
                    }
                )
                enriched.append(
                    {
                        **row,
                        "job_id": task_id,
                        "task_id": task_id,
                        "detail": detail,
                    }
                )
            except Exception:
                # The durable REST event remains useful even when current host
                # catalogs cannot prove richer completion metadata. Link
                # Dashboard v2 opts out to avoid generic scheduled-task rows.
                if preserve_unenriched:
                    enriched.append(row)
                continue
        return enriched

    async def _canonical_cron_job_id(self, session_id: str, agent_id: str) -> str:
        """Resolve only cron-owned identity through verified compression edges."""
        direct = _cron_job_id(session_id)
        if direct:
            return direct

        current = session_id
        visited: set[str] = set()
        for _ in range(32):
            if current in visited:
                break
            visited.add(current)
            child = _object(
                await self._session_detail(current, agent_id),
                "Hermes session detail",
            )
            if _coordinate(child.get("id"), 180) != current:
                break
            parent_id = _optional_coordinate(child.get("parent_session_id"), 180)
            if parent_id is None or parent_id in visited:
                break
            parent = _object(
                await self._session_detail(parent_id, agent_id),
                "Hermes parent session detail",
            )
            child_source = _coordinate(child.get("source"), 80)
            parent_source = _coordinate(parent.get("source"), 80)
            child_model = _optional_object(child.get("model_config"))
            if (
                _coordinate(parent.get("id"), 180) != parent_id
                or child_source != "cron"
                or parent_source != child_source
                or any(
                    child_model.get(marker) is not None
                    for marker in ("_branched_from", "_delegate_from", "_reset_from")
                )
                or parent.get("end_reason") != "compression"
                or _timestamp(child.get("started_at"))
                < _timestamp(parent.get("ended_at"))
            ):
                break
            canonical = _cron_job_id(parent_id)
            if canonical:
                return canonical
            current = parent_id
        raise WorkspaceControlError("Hermes cron session identity is unavailable")

    async def _dismiss_event_ids(
        self, ids: list[str], *, created_before: int | None = None
    ) -> int:
        dismissed = 0
        for start in range(0, len(ids), 200):
            count = await asyncio.to_thread(
                self.service.store.dismiss_events,
                event_ids=ids[start : start + 200],
                created_before=created_before,
            )
            dismissed += _nonnegative_integer(count, maximum=10_000_000)
        return dismissed

    async def _scheduled_task_action(self, payload: dict[str, Any], action: Any) -> dict[str, Any]:
        task_id, agent_id = _task_coordinate(payload)
        job = action(task_id, agent_id)
        if inspect.isawaitable(job):
            job = await job
        return {"task": _task_projection(job, default_agent_id=agent_id)}

    async def _profile_records(self) -> list[dict[str, Any]]:
        def load() -> list[dict[str, Any]]:
            from hermes_cli.profiles import (
                get_profile_dir,
                list_profile_names,
                profile_exists,
                read_profile_meta,
            )

            records = []
            for name in list_profile_names():
                if not profile_exists(name):
                    continue
                path = get_profile_dir(name)
                meta = read_profile_meta(path)
                records.append(
                    {
                        "id": name,
                        "display_name": meta.get("display_name", ""),
                        # Older Hermes profiles can persist the presentation
                        # name under ui_meta.displayName. Keep this local and
                        # project only the bounded display value.
                        "ui_display_name": _profile_ui_display_name(path),
                        "description": meta.get("description", ""),
                        "is_default": name == "default",
                        "has_avatar": _profile_has_avatar(path),
                    }
                )
            return records

        return await asyncio.to_thread(load)

    async def _profile_soul(self, agent_id: str) -> str:
        def load() -> str:
            from hermes_cli.profiles import get_profile_dir, profile_exists

            if not profile_exists(agent_id):
                raise WorkspaceControlError("The selected agent is unavailable")
            path = get_profile_dir(agent_id) / "SOUL.md"
            if not path.exists():
                return ""
            content = path.read_text(encoding="utf-8")
            return _text(content, 256_000, allow_empty=True)

        return await asyncio.to_thread(load)

    async def _create_profile(
        self,
        *,
        agent_id: str,
        display_name: str,
        description: str,
        instructions: str,
    ) -> None:
        def create() -> None:
            from hermes_cli import profiles
            from utils import atomic_write_text

            path = profiles.create_profile(
                name=agent_id,
                no_skills=False,
                description=description,
            )
            profiles.seed_profile_skills(path, quiet=True)
            if not profiles.check_alias_collision(agent_id):
                profiles.create_wrapper_script(agent_id)
            profiles.set_profile_display_name(agent_id, display_name)
            atomic_write_text(
                path / "SOUL.md",
                instructions,
                preserve_mode=True,
                create_mode=0o644,
            )

        await asyncio.to_thread(create)

    async def _update_profile(
        self,
        *,
        agent_id: str,
        display_name: str,
        description: str,
        instructions: str | None,
        expected_instructions_sha256: str | None,
    ) -> None:
        def update() -> None:
            from hermes_cli import profiles
            from utils import atomic_write_text

            if not profiles.profile_exists(agent_id):
                raise WorkspaceControlError("The selected agent is unavailable")
            path = profiles.get_profile_dir(agent_id)
            profiles.write_profile_meta(
                path,
                description=description,
                description_auto=False,
                display_name=display_name,
            )
            if instructions is not None:
                soul_path = path / "SOUL.md"
                current = (
                    soul_path.read_text(encoding="utf-8")
                    if soul_path.exists()
                    else ""
                )
                if (
                    expected_instructions_sha256 is None
                    or not hmac.compare_digest(
                        _soul_digest(current),
                        expected_instructions_sha256,
                    )
                ):
                    raise WorkspaceConflictError(
                        "SOUL changed before the update was committed"
                    )
                atomic_write_text(
                    soul_path,
                    instructions,
                    preserve_mode=True,
                    create_mode=0o644,
                )

        await asyncio.to_thread(update)

    async def _profile_avatar(self, agent_id: str) -> dict[str, Any]:
        return await self._profile_asset_request(
            "profiles.get_asset",
            {"name": agent_id, "asset": "avatar"},
        )

    async def _set_profile_avatar(self, agent_id: str, avatar: dict[str, Any] | None) -> None:
        params: dict[str, Any] = {"name": agent_id, "asset": "avatar"}
        if avatar is None:
            params["clear"] = True
        else:
            params["data"] = _agent_avatar_payload(avatar)["data"]
        result = await self._profile_asset_request("profiles.set_asset", params)
        if result.get("ok") is not True:
            raise WorkspaceControlError("Hermes could not update the agent avatar")

    async def _profile_asset_request(
        self,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._hermes_request(
            method,
            params,
            unavailable_message="Hermes profile assets are unavailable",
            request_id="loopdy-profile-asset",
        )

    async def _hermes_request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        unavailable_message: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        def dispatch() -> dict[str, Any]:
            from tui_gateway.server import handle_request

            resolved_request_id = request_id or f"loopdy-{method}"
            response = handle_request({
                "jsonrpc": "2.0",
                "id": resolved_request_id,
                "method": method,
                "params": params,
            })
            error = response.get("error") if isinstance(response, dict) else None
            if (
                isinstance(error, dict)
                and error.get("code") == -32601
            ):
                raise _HermesMethodUnavailable(unavailable_message)
            if (
                not isinstance(response, dict)
                or response.get("id") != resolved_request_id
                or "error" in response
                or not isinstance(response.get("result"), dict)
            ):
                raise WorkspaceControlError(unavailable_message)
            return dict(response["result"])

        return await asyncio.to_thread(dispatch)

    async def _profile_config(self, agent_id: str) -> dict[str, Any]:
        try:
            result = await self._hermes_request(
                "config.get",
                {"profile": agent_id, "key": "full"},
                unavailable_message="Hermes agent configuration is unavailable",
            )
            return _object(result.get("config"), "Hermes config")
        except (ImportError, _HermesMethodUnavailable):
            from hermes_cli.web_server import get_config

            result = get_config(profile=agent_id)
            if inspect.isawaitable(result):
                result = await result
            return _object(result, "Hermes config")

    async def _model_options(self, agent_id: str) -> dict[str, Any]:
        try:
            return await self._hermes_request(
                "model.options",
                {"profile": agent_id, "explicit_only": True},
                unavailable_message="Hermes model options are unavailable",
            )
        except (ImportError, _HermesMethodUnavailable):
            from hermes_cli.web_server import get_model_options

            parameters = inspect.signature(get_model_options).parameters.values()
            supports_explicit_filter = any(
                parameter.name == "explicit_only"
                or parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters
            )
            keyword_arguments: dict[str, Any] = {"profile": agent_id}
            if supports_explicit_filter:
                keyword_arguments["explicit_only"] = True
            result = get_model_options(**keyword_arguments)
            if inspect.isawaitable(result):
                return await result
            return _object(result, "model options")

    async def _save_profile_config(
        self, agent_id: str, config: dict[str, Any]
    ) -> None:
        from hermes_cli.web_models import ConfigUpdate
        from hermes_cli.web_server import update_config

        await update_config(
            ConfigUpdate(config=config, profile=agent_id),
            profile=agent_id,
        )

    async def _skills_catalog(self, agent_id: str) -> list[dict[str, Any]]:
        from hermes_cli.web_server import get_skills

        return await get_skills(profile=agent_id)

    async def _plugins_catalog(self) -> list[dict[str, Any]]:
        from hermes_cli.plugins import get_plugin_manager

        return get_plugin_manager().list_plugins()

    async def _mcp_catalog(self, agent_id: str) -> dict[str, Any]:
        from hermes_cli.web_server import list_mcp_servers

        return await list_mcp_servers(profile=agent_id)

    async def _projects_catalog(self, agent_id: str) -> dict[str, Any]:
        from hermes_cli import profiles
        from hermes_cli import projects_db
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )

        def load() -> dict[str, Any]:
            if not profiles.profile_exists(agent_id):
                raise WorkspaceControlError("The selected agent is unavailable")
            token = set_hermes_home_override(profiles.get_profile_dir(agent_id))
            try:
                with projects_db.connect_closing() as connection:
                    return {
                        "active_id": projects_db.get_active_id(connection),
                        "projects": [
                            project.to_dict()
                            for project in projects_db.list_projects(
                                connection, include_archived=False
                            )
                        ],
                    }
            finally:
                reset_hermes_home_override(token)

        return await asyncio.to_thread(load)

    async def _set_active_project(self, agent_id: str, project_id: str) -> str:
        from hermes_cli import profiles
        from hermes_cli import projects_db
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )

        def save() -> str:
            if not profiles.profile_exists(agent_id):
                raise WorkspaceControlError("The selected agent is unavailable")
            token = set_hermes_home_override(profiles.get_profile_dir(agent_id))
            try:
                with projects_db.connect_closing() as connection:
                    project = projects_db.get_project(connection, project_id)
                    if project is None or project.archived:
                        raise WorkspaceControlError("Workspace is unavailable")
                    primary_path = project.primary_path or next(
                        (folder.path for folder in project.folders if folder.is_primary),
                        project.folders[0].path if project.folders else "",
                    )
                    resolved_path = _canonical_project_directory(primary_path)
                    projects_db.set_active(connection, project_id)
                    return resolved_path
            finally:
                reset_hermes_home_override(token)

        return await asyncio.to_thread(save)

    async def _project_directory(self, agent_id: str, project_id: str) -> str:
        raw = _object(
            await self._projects_catalog(agent_id),
            "Hermes project catalog",
        )
        rows = raw.get("projects")
        if not isinstance(rows, list) or len(rows) > 256:
            raise WorkspaceControlError("Hermes project catalog is invalid")
        matches = [
            _object(row, "Hermes project")
            for row in rows
            if isinstance(row, dict)
            and row.get("id") == project_id
            and row.get("archived") is not True
        ]
        if len(matches) != 1:
            raise WorkspaceControlError("Workspace is unavailable")
        return _canonical_project_directory(_project_primary_path(matches[0]))

    async def _create_project(
        self,
        agent_id: str,
        name: str,
        folder_path: str,
    ) -> None:
        from hermes_cli import profiles
        from hermes_cli import projects_db
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )

        def save() -> None:
            if not profiles.profile_exists(agent_id):
                raise WorkspaceControlError("The selected agent is unavailable")
            token = set_hermes_home_override(profiles.get_profile_dir(agent_id))
            try:
                with projects_db.connect_closing() as connection:
                    project_id = projects_db.create_project(
                        connection,
                        name=name,
                        folders=[folder_path],
                        primary_path=folder_path,
                    )
                    projects_db.set_active(connection, project_id)
            finally:
                reset_hermes_home_override(token)

        await asyncio.to_thread(save)

    async def _archive_project(self, agent_id: str, project_id: str) -> None:
        from hermes_cli import profiles
        from hermes_cli import projects_db
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )

        def save() -> None:
            if not profiles.profile_exists(agent_id):
                raise WorkspaceControlError("The selected agent is unavailable")
            token = set_hermes_home_override(profiles.get_profile_dir(agent_id))
            try:
                with projects_db.connect_closing() as connection:
                    project = projects_db.get_project(connection, project_id)
                    if project is None or project.archived:
                        raise WorkspaceControlError("Workspace is unavailable")
                    if not projects_db.archive_project(connection, project.id):
                        raise WorkspaceControlError("Workspace could not be archived")
                    if projects_db.get_active_id(connection) == project.id:
                        projects_db.set_active(connection, None)
            finally:
                reset_hermes_home_override(token)

        await asyncio.to_thread(save)

    async def _session_catalog(self, agent_id: str | None) -> dict[str, Any]:
        from hermes_cli.web_routers.profiles import get_profiles_sessions

        return await asyncio.to_thread(
            get_profiles_sessions,
            limit=500,
            offset=0,
            min_messages=0,
            archived="exclude",
            order="recent",
            profile=agent_id or "all",
            source=None,
            sources=None,
            exclude_sources="cron",
            full=False,
        )

    async def _session_messages(
        self,
        stored_id: str,
        agent_id: str,
        *,
        include_compacted: bool = True,
        offset: int = 0,
    ) -> dict[str, Any]:
        from hermes_cli.web_routers.sessions import get_session_messages

        return await get_session_messages(
            stored_id,
            profile=agent_id,
            limit=500,
            offset=offset,
            order="latest",
            include_compacted=include_compacted,
        )

    async def _session_detail(self, session_id: str, agent_id: str) -> dict[str, Any]:
        from hermes_cli.web_routers.sessions import get_session_detail

        return await get_session_detail(session_id, profile=agent_id)

    async def _cron_list(self, agent_id: str | None) -> list[dict[str, Any]]:
        from hermes_cli.web_server import _list_cron_jobs_sync

        return await asyncio.to_thread(_list_cron_jobs_sync, agent_id or "all")

    async def _cron_delivery_targets(self) -> list[dict[str, Any]]:
        from cron.scheduler import cron_delivery_targets

        return await asyncio.to_thread(cron_delivery_targets)

    async def _cron_create(
        self, agent_id: str, values: dict[str, Any]
    ) -> dict[str, Any]:
        from hermes_cli.web_models import CronJobCreate
        from hermes_cli.web_server import _create_cron_job_sync

        return await asyncio.to_thread(
            _create_cron_job_sync,
            CronJobCreate(**values),
            agent_id,
        )

    async def _cron_update(
        self, task_id: str, agent_id: str, updates: dict[str, Any]
    ) -> dict[str, Any]:
        from hermes_cli.web_models import CronJobUpdate
        from hermes_cli.web_server import _update_cron_job_sync

        return await asyncio.to_thread(
            _update_cron_job_sync,
            task_id,
            CronJobUpdate(updates=updates),
            agent_id,
        )

    async def _cron_pause(self, task_id: str, agent_id: str) -> dict[str, Any]:
        from hermes_cli.web_server import _pause_cron_job_sync

        return await asyncio.to_thread(_pause_cron_job_sync, task_id, agent_id)

    async def _cron_resume(self, task_id: str, agent_id: str) -> dict[str, Any]:
        from hermes_cli.web_server import _resume_cron_job_sync

        return await asyncio.to_thread(_resume_cron_job_sync, task_id, agent_id)

    async def _cron_run(self, task_id: str, agent_id: str) -> dict[str, Any]:
        from hermes_cli.web_server import _trigger_cron_job_sync

        return await asyncio.to_thread(_trigger_cron_job_sync, task_id, agent_id)

    async def _cron_delete(self, task_id: str, agent_id: str) -> None:
        from hermes_cli.web_server import _delete_cron_job_sync

        await asyncio.to_thread(_delete_cron_job_sync, task_id, agent_id)


def _empty_payload(payload: Any) -> None:
    if not isinstance(payload, dict) or payload:
        raise WorkspaceControlError("Workspace payload must be empty")


def _project_primary_path(project: dict[str, Any]) -> str:
    direct = project.get("primary_path")
    if isinstance(direct, str) and direct.strip():
        return _absolute_project_path(direct)
    folders = project.get("folders")
    if not isinstance(folders, list) or not folders:
        raise WorkspaceControlError("Project Git Project has no registered folder")
    primary = next(
        (
            row.get("path")
            for row in folders
            if isinstance(row, dict) and row.get("is_primary") is True
        ),
        None,
    )
    if primary is None and isinstance(folders[0], dict):
        primary = folders[0].get("path")
    return _absolute_project_path(primary)


def _absolute_project_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkspaceControlError("Project Git Project path is invalid")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise WorkspaceControlError("Project Git Project path is invalid")
    return str(candidate.resolve(strict=False))


def _same_project_path(left: Any, right: Any) -> bool:
    left_path = Path(_absolute_project_path(left))
    right_path = Path(_absolute_project_path(right))
    if left_path == right_path:
        return True
    try:
        return left_path.samefile(right_path)
    except OSError:
        return False


def _project_git_status_token(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise WorkspaceControlError("Project Git status token is invalid")
    return value


def _project_git_relative_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4_096
        or value.startswith(("/", "\\", "-"))
        or "\\" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 32 for character in value)
        or "://" in value
    ):
        raise WorkspaceControlError("Project Git path is invalid")
    return value


def _project_git_choice(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise WorkspaceControlError("Project Git operation is invalid")
    return value


def _project_git_ref(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 180
        or value.startswith(("-", "/"))
        or value.endswith(("/", "."))
        or ".." in value
        or ":" in value
        or "\\" in value
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise WorkspaceControlError(f"Project Git {label} is invalid")
    return value


def _project_git_operation_input(operation: str, value: Any) -> dict[str, Any]:
    values = _object(value, "Project Git input")
    expected = {
        "stage": {"mode", "paths"},
        "commit": {"message"},
        "fetch": {"remote"},
        "pull": {"remote", "branch"},
        "push": {"remote", "branch"},
    }[operation]
    if set(values) != expected:
        raise WorkspaceControlError("Project Git input is invalid")
    if operation == "stage":
        raw_paths = values.get("paths")
        if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 500:
            raise WorkspaceControlError("Project Git paths are invalid")
        paths = [_project_git_relative_path(path) for path in raw_paths]
        if len(set(paths)) != len(paths):
            raise WorkspaceControlError("Project Git paths are invalid")
        return {
            "mode": _project_git_choice(values.get("mode"), {"stage", "unstage"}),
            "paths": paths,
        }
    if operation == "commit":
        message = values.get("message")
        if (
            not isinstance(message, str)
            or not message.strip()
            or len(message.encode("utf-8")) > 10_000
            or any(ord(character) < 32 and character not in "\n\t" for character in message)
        ):
            raise WorkspaceControlError("Project Git commit message is invalid")
        return {"message": message}
    result = {"remote": _project_git_ref(values.get("remote"), "remote")}
    if operation in {"pull", "push"}:
        result["branch"] = _project_git_ref(values.get("branch"), "branch")
    return result


def _project_git_policy(workspace_id: str, project_root: str) -> dict[str, Any]:
    default = {
        "visibility": "private",
        "operations": ["status"],
        "remotes": [],
        "branches": [],
        "mutations_enabled": False,
    }
    raw = os.getenv("LOOPDY_WORKSPACE_GIT_CONFIG", "").strip()
    if not raw:
        return default
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WorkspaceControlError("Project Git host policy is invalid") from exc
    if not isinstance(configured, list) or len(configured) > 256:
        raise WorkspaceControlError("Project Git host policy is invalid")
    matches = [
        row
        for row in configured
        if isinstance(row, dict) and row.get("workspace_id") == workspace_id
    ]
    if len(matches) > 1:
        raise WorkspaceControlError("Project Git host policy is ambiguous")
    if not matches:
        return default
    selected = matches[0]
    configured_root = selected.get("root")
    if _absolute_project_path(configured_root) != project_root:
        return default
    operations = selected.get("operations")
    remotes = selected.get("remotes")
    branches = selected.get("branches")
    if (
        not isinstance(operations, list)
        or not isinstance(remotes, list)
        or not isinstance(branches, list)
    ):
        raise WorkspaceControlError("Project Git host policy is invalid")
    allowed = {"status", "stage", "commit", "fetch", "pull", "push"}
    operation_set = {str(item) for item in operations}
    if not operation_set or not operation_set <= allowed:
        raise WorkspaceControlError("Project Git host policy is invalid")
    visibility = selected.get("visibility", "private")
    if visibility not in {"private", "public"}:
        raise WorkspaceControlError("Project Git host policy is invalid")
    return {
        "visibility": visibility,
        "operations": sorted(operation_set | {"status"}),
        "remotes": [_project_git_ref(item, "remote") for item in remotes],
        "branches": [_project_git_ref(item, "branch") for item in branches],
        "mutations_enabled": selected.get("mutations_enabled") is True,
    }


def _project_git_wire(value: Any) -> Any:
    key_map = {
        "schema_version": "schemaVersion",
        "arbitrary_command": "arbitraryCommand",
        "workspace_id": "workspaceId",
        "mutations_enabled": "mutationsEnabled",
        "status_token": "statusToken",
        "original_path": "originalPath",
        "is_binary": "isBinary",
        "files_page": "filesPage",
        "conflicts_page": "conflictsPage",
        "next_offset": "nextOffset",
        "old_line": "oldLine",
        "new_line": "newLine",
        "confirmation_token": "confirmationToken",
        "operation_digest": "operationDigest",
        "expires_at": "expiresAt",
        "operation_id": "operationId",
        "commit_oid": "commitOid",
        "parent_oid": "parentOid",
        "tree_oid": "treeOid",
        "updated_refs": "updatedRefs",
        "rule_id": "ruleId",
    }
    if isinstance(value, list):
        return [_project_git_wire(item) for item in value]
    if isinstance(value, dict):
        projected: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
                raise WorkspaceControlError("Project Git response is invalid")
            projected[key_map.get(key, key)] = _project_git_wire(item)
        return projected
    return _workspace_json(value, depth=1)


def _project_git_control_error(error: WorkspaceGitError) -> WorkspaceControlError:
    code_map = {
        "STATUS_STALE": ("status_changed", "conflict", "Project changes changed. Refresh and try again."),
        "CONFIRMATION_INVALID": ("confirmation_expired", "conflict", "Prepare this Git operation again."),
        "IDEMPOTENCY_CONFLICT": ("idempotency_conflict", "conflict", "This Git operation identity was already used."),
        "INVALID_REQUEST": ("invalid_request", "failed", "The Git request is invalid."),
        "INVALID_PATH": ("invalid_path", "failed", "The selected Project path is invalid."),
        "UNSUPPORTED_PATH_ENCODING": ("diff_unavailable", "failed", "This Project path cannot be displayed."),
        "WORKSPACE_NOT_ALLOWED": ("project_unavailable", "failed", "Project Git is unavailable for this Project."),
        "OPERATION_NOT_ALLOWED": ("operation_disabled", "failed", "This Git operation is disabled by the host."),
        "GIT_UNAVAILABLE": ("git_unavailable", "failed", "Git is unavailable for this Project."),
        "GIT_TIMEOUT": ("git_timeout", "failed", "Git did not finish in time. Retry after refreshing."),
        "REMOTE_UNAVAILABLE": ("remote_unavailable", "failed", "The configured Git remote is unavailable."),
        "AUTHENTICATION_FAILED": ("authentication_failed", "failed", "Git authentication failed on the Hermes host."),
        "SECRET_SCAN_BLOCKED": ("sensitive_data_blocked", "failed", "The staged changes require review before committing."),
        "PUBLIC_REPO_SAFETY_BLOCK": ("sensitive_data_blocked", "failed", "The outgoing changes require review before continuing."),
        "BRANCH_MISMATCH": ("branch_mismatch", "failed", "The current branch is not enabled for this operation."),
        "UPSTREAM_REQUIRED": ("upstream_required", "failed", "This branch does not track the enabled upstream."),
        "NON_FAST_FORWARD": ("non_fast_forward", "failed", "The branch cannot be updated safely without review."),
        "WORKTREE_CONFLICTED": ("worktree_conflicted", "failed", "Resolve Project conflicts before continuing."),
        "WORKTREE_NOT_CLEAN": ("worktree_not_clean", "failed", "The Project must be clean before this operation."),
        "NOTHING_TO_STAGE": ("nothing_to_stage", "failed", "The selected files cannot be staged in their current state."),
        "NOTHING_TO_COMMIT": ("nothing_to_commit", "failed", "Stage changes before committing."),
        "NOTHING_TO_PULL": ("nothing_to_pull", "failed", "The Project is already up to date."),
        "NOTHING_TO_PUSH": ("nothing_to_push", "failed", "The upstream already has this branch."),
        "GIT_OUTCOME_UNKNOWN": ("outcome_unknown", "conflict", "The Git result is uncertain. Refresh before continuing."),
    }
    code, status, message = code_map.get(
        error.code,
        ("project_git_failed", "failed", "Hermes could not complete this Git operation."),
    )
    return WorkspaceControlError(message, code=code, status=status)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkspaceControlError(f"{label} is invalid")
    return value


def _optional_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any, maximum: int, *, allow_empty: bool = False) -> str:
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str):
        raise WorkspaceControlError("Workspace text is invalid")
    normalized = value.strip()
    if (not normalized and not allow_empty) or len(value.encode("utf-8")) > maximum:
        raise WorkspaceControlError("Workspace text is invalid")
    if any(ord(character) < 32 and character not in "\n\t\r" for character in value):
        raise WorkspaceControlError("Workspace text is invalid")
    return value if allow_empty else normalized


def _soul_digest(content: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(content.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")


def _soul_digest_coordinate(value: Any) -> str:
    digest = _coordinate(value, 43)
    if len(digest) != 43 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", digest):
        raise WorkspaceControlError("SOUL digest is invalid")
    return digest


def _utf8_prefix(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", errors="ignore").rstrip()


def _agent_id(value: Any) -> str:
    candidate = _text(value, 64)
    if not _AGENT_ID.fullmatch(candidate):
        raise WorkspaceControlError("Agent identifier is invalid")
    return candidate


def _coordinate(value: Any, maximum: int) -> str:
    candidate = _text(value, maximum)
    if any(character.isspace() for character in candidate):
        raise WorkspaceControlError("Workspace coordinate is invalid")
    return candidate


def _optional_coordinate(value: Any, maximum: int) -> str | None:
    if value is None or value == "":
        return None
    return _coordinate(value, maximum)


def _nonnegative_integer(value: Any, *, maximum: int) -> int:
    if isinstance(value, bool):
        raise WorkspaceControlError("Workspace number is invalid")
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or value < 0 or value > maximum:
        raise WorkspaceControlError("Workspace number is invalid")
    return value


def _canonical_project_directory(value: Any) -> str:
    raw = _text(value, 4_096)
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise WorkspaceControlError("Workspace folder path is invalid")
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir() or not os.access(resolved, os.R_OK | os.X_OK):
            raise WorkspaceControlError("Workspace folder is not readable")
    except WorkspaceControlError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WorkspaceControlError("Workspace folder is unavailable") from exc
    return str(resolved)


def _project_directory_prefix(value: Any) -> str:
    prefix = _text(value, 255, allow_empty=True)
    if prefix in {".", ".."} or "/" in prefix or "\\" in prefix:
        raise WorkspaceControlError("Workspace folder prefix is invalid")
    return prefix


def _project_directory_page(
    parent_path: str,
    prefix: str,
    offset: int,
    limit: int,
) -> dict[str, Any]:
    folded_prefix = prefix.casefold()
    folders: list[dict[str, str]] = []
    try:
        with os.scandir(parent_path) as entries:
            for entry in entries:
                if (
                    entry.name.startswith(".")
                    or entry.name in _PROJECT_DIRECTORY_HIDDEN
                    or not entry.name.casefold().startswith(folded_prefix)
                    or entry.is_symlink()
                    or not entry.is_dir(follow_symlinks=False)
                ):
                    continue
                folders.append({
                    "name": entry.name,
                    "path": str(Path(parent_path, entry.name)),
                })
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        raise WorkspaceControlError("Workspace folder is not readable") from exc
    folders.sort(key=lambda item: (item["name"].casefold(), item["name"]))
    page = folders[offset : offset + limit]
    next_offset = offset + len(page)
    return {
        "parentPath": parent_path,
        "folders": page,
        "nextOffset": next_offset if next_offset < len(folders) else None,
    }


def _timestamp(value: Any) -> int:
    if isinstance(value, bool):
        raise WorkspaceControlError("Workspace timestamp is invalid")
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError as exc:
            raise WorkspaceControlError("Workspace timestamp is invalid") from exc
    if not isinstance(value, (int, float)) or value < 0 or value > 4_102_444_800:
        raise WorkspaceControlError("Workspace timestamp is invalid")
    return int(value)


def _agent_id_from_name(value: str) -> str:
    folded = value.casefold()
    parts = re.findall(r"[a-z0-9]+", folded)
    candidate = "-".join(parts)[:64] or "agent"
    return _agent_id(candidate)


def _profile_ui_display_name(path: Any) -> str:
    """Read the user-facing name from Hermes profile metadata locally."""
    try:
        import yaml

        document = yaml.safe_load((path / "profile.yaml").read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            return ""
        ui_meta = document.get("ui_meta")
        if not isinstance(ui_meta, dict):
            return ""
        return _text(ui_meta.get("displayName"), 80, allow_empty=True)
    except Exception:
        return ""


def _profile_has_avatar(path: Any) -> bool:
    try:
        from pathlib import Path

        assets = Path(path) / "assets"
        return any((assets / f"avatar.{ext}").is_file() for ext in ("png", "jpg", "webp"))
    except Exception:
        return False


def _stored_session_id_for_visible(
    catalog: dict[str, Any], visible_id: str
) -> str | None:
    rows = catalog.get("sessions")
    if not isinstance(rows, list):
        return None
    # A durable id always wins over a chat alias. This keeps reset siblings
    # independently addressable even when a legacy chat id happens to collide
    # with another row's stored coordinate.
    for row in rows:
        if not isinstance(row, dict):
            continue
        stored_id = row.get("id")
        if stored_id == visible_id:
            try:
                return _coordinate(stored_id, 160)
            except WorkspaceControlError:
                return None
    for row in rows:
        if not isinstance(row, dict) or row.get("chat_id") != visible_id:
            continue
        try:
            return _coordinate(row.get("id"), 160)
        except WorkspaceControlError:
            return None
    return None


def _display_name(agent_id: str) -> str:
    return " ".join(part.capitalize() for part in agent_id.split("-") if part)


def _agent_draft(payload: dict[str, Any]) -> dict[str, Any]:
    values = _object(payload, "workspace payload")
    if set(values) != {"agent"}:
        raise WorkspaceControlError("Agent payload is invalid")
    agent = _object(values.get("agent"), "agent")
    allowed = {"name", "role", "summary", "instructions", "isDefault", "avatar"}
    if set(agent) - allowed or not {"name", "role", "summary", "instructions"}.issubset(agent):
        raise WorkspaceControlError("Agent payload is invalid")
    draft = {
        "name": _text(agent.get("name"), 80),
        "role": _text(agent.get("role"), 160),
        "summary": _text(agent.get("summary"), 4_096),
        "instructions": _text(agent.get("instructions"), 256_000),
    }
    if "avatar" in agent:
        draft["avatar"] = _agent_avatar_payload(agent.get("avatar"))
    return draft


def _agent_avatar_payload(value: Any) -> dict[str, Any]:
    avatar = _object(value, "agent avatar")
    if set(avatar) != {"mimeType", "byteCount", "sha256", "data"}:
        raise WorkspaceControlError("Agent avatar payload is invalid")
    mime_type = avatar.get("mimeType")
    if mime_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise WorkspaceControlError("Agent avatar payload is invalid")
    byte_count = avatar.get("byteCount")
    if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count <= 0:
        raise WorkspaceControlError("Agent avatar payload is invalid")
    sha256 = _text(avatar.get("sha256"), 128)
    if len(sha256) < 16:
        raise WorkspaceControlError("Agent avatar payload is invalid")
    data = _text(avatar.get("data"), 2_800_000)
    if not data.startswith(f"data:{mime_type};base64,"):
        raise WorkspaceControlError("Agent avatar payload is invalid")
    return {
        "mimeType": mime_type,
        "byteCount": byte_count,
        "sha256": sha256,
        "data": data,
    }


def _agent_avatar_projection(value: dict[str, Any]) -> dict[str, Any]:
    import base64
    import hashlib

    mime_type = value.get("mime")
    data = value.get("data")
    byte_count = value.get("size")
    if (
        mime_type not in {"image/png", "image/jpeg", "image/webp"}
        or not isinstance(data, str)
        or not data.startswith(f"data:{mime_type};base64,")
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
    ):
        raise WorkspaceControlError("Hermes returned an invalid agent avatar")
    try:
        blob = base64.b64decode(data.split(",", 1)[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise WorkspaceControlError("Hermes returned an invalid agent avatar") from exc
    if len(blob) != byte_count:
        raise WorkspaceControlError("Hermes returned an invalid agent avatar")
    projected = {
        "mimeType": mime_type,
        "byteCount": byte_count,
        "sha256": base64.urlsafe_b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="),
        "data": data,
    }
    return _agent_avatar_payload(projected)


def _agent_payload_id(payload: dict[str, Any]) -> str:
    values = _object(payload, "workspace payload")
    if set(values) != {"agentId"}:
        raise WorkspaceControlError("Agent payload is invalid")
    return _agent_id(values.get("agentId"))


def _identifier(value: Any, maximum: int) -> str:
    candidate = _text(value, maximum, allow_empty=True).strip()
    if any(character.isspace() for character in candidate):
        raise WorkspaceControlError("Runtime identifier is invalid")
    return candidate


def _model_identifier(value: Any, maximum: int) -> str:
    """Validate a model label without treating spaces as unsafe syntax.

    Hermes supports named model presets (for example, "Frontier Tuned").
    These are still opaque data: whitespace is valid, while control
    characters and leading/trailing whitespace are not.
    """
    candidate = _text(value, maximum, allow_empty=True).strip()
    if not candidate:
        return ""
    if candidate != str(value).strip() or not candidate.isprintable():
        raise WorkspaceControlError("Runtime model identifier is invalid")
    return candidate


def _reasoning(value: Any) -> str:
    candidate = _identifier(value, 32)
    if candidate not in _REASONING_VALUES:
        raise WorkspaceControlError("Reasoning effort is invalid")
    return candidate


def _selection(provider: Any, model: Any, reasoning: Any) -> dict[str, str]:
    return {
        "providerId": _identifier(provider, 128),
        "modelId": _model_identifier(model, 256),
        "reasoningEffort": _reasoning(reasoning),
    }


def _defaults(value: Any) -> dict[str, dict[str, str]]:
    defaults = _object(value, "agent defaults")
    expected = {"mainChats", "subagents", "scheduledTasks"}
    if set(defaults) != expected:
        raise WorkspaceControlError("Agent defaults are invalid")
    projected: dict[str, dict[str, str]] = {}
    for scope in sorted(expected):
        selection = _object(defaults.get(scope), "runtime selection")
        if set(selection) != {"providerId", "modelId", "reasoningEffort"}:
            raise WorkspaceControlError("Runtime selection is invalid")
        projected[scope] = _selection(
            selection.get("providerId"),
            selection.get("modelId"),
            selection.get("reasoningEffort"),
        )
    return projected


def _provider_projection(value: Any) -> list[dict[str, Any]]:
    options = _object(value, "model options")
    rows = options.get("providers")
    if not isinstance(rows, list) or len(rows) > 64:
        raise WorkspaceControlError("Model providers are invalid")
    current = _identifier(options.get("provider"), 128)
    providers = []
    for row in rows:
        source = _object(row, "model provider")
        provider_id = _identifier(source.get("slug", source.get("id")), 128)
        if not provider_id:
            raise WorkspaceControlError("Model provider is invalid")
        name = _text(source.get("name", source.get("label", provider_id)), 80)
        models = source.get("models")
        if not isinstance(models, list) or len(models) > 800:
            raise WorkspaceControlError("Provider model catalog is invalid")
        # Current Hermes intentionally includes canonical providers that are
        # not configured for this profile as empty rows. They are catalog
        # metadata, not selectable picker sections.
        if not models:
            continue
        projected_models = [_model_identifier(model, 256) for model in models]
        if any(not model for model in projected_models) or len(set(projected_models)) != len(projected_models):
            raise WorkspaceControlError("Provider model catalog is invalid")
        providers.append(
            {
                "id": provider_id,
                "name": name,
                "isCurrent": bool(source.get("is_current", provider_id == current)),
                "isCustom": bool(source.get("is_user_defined", False)),
                "models": projected_models,
            }
        )
    return providers


def _scheduled_task_draft(payload: Any) -> dict[str, str]:
    values = _object(payload, "workspace payload")
    if set(values) != {"agentId", "name", "instructions", "schedule", "delivery"}:
        raise WorkspaceControlError("Scheduled task payload is invalid")
    return {
        "agentId": _agent_id(values.get("agentId")),
        "name": _text(values.get("name"), 240),
        "instructions": _text(values.get("instructions"), 256_000),
        "schedule": _text(values.get("schedule"), 2_048),
        "delivery": _text(values.get("delivery"), 512),
    }


def _delivery_target_catalog(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise WorkspaceControlError("Hermes delivery target catalog is invalid")
    targets = [{
        "id": "local",
        "name": "Local (save only)",
        "homeTargetSet": True,
    }]
    seen = {"local"}
    for raw in value:
        source = _object(raw, "Hermes delivery target")
        target_id = _text(source.get("id"), 160)
        if target_id in seen:
            raise WorkspaceControlError("Hermes delivery target catalog is invalid")
        home_target_set = source.get("home_target_set")
        if type(home_target_set) is not bool:
            raise WorkspaceControlError("Hermes delivery target catalog is invalid")
        seen.add(target_id)
        targets.append({
            "id": target_id,
            "name": _text(source.get("name"), 160),
            "homeTargetSet": home_target_set,
        })
    return targets


def _scheduled_task_delivery(value: Any, raw_targets: Any) -> str:
    delivery = _text(value, 512)
    targets = _delivery_target_catalog(raw_targets)
    exact = next((target for target in targets if target["id"] == delivery), None)
    if exact is not None:
        if exact["homeTargetSet"]:
            return delivery
        raise WorkspaceControlError("Scheduled task delivery home target is unavailable")

    if (
        "," in delivery
        or any(character.isspace() for character in delivery)
        or ":" not in delivery
    ):
        raise WorkspaceControlError("Scheduled task delivery is invalid")
    platform, target = delivery.split(":", 1)
    known_platforms = {
        item["id"] for item in targets
        if item["id"] not in {"local"} and ":" not in item["id"]
    }
    if platform not in known_platforms or not target or target.startswith(":"):
        raise WorkspaceControlError("Scheduled task delivery is invalid")
    return delivery


def _task_coordinate(payload: Any) -> tuple[str, str]:
    values = _object(payload, "workspace payload")
    if set(values) != {"taskId", "agentId"}:
        raise WorkspaceControlError("Scheduled task coordinate is invalid")
    return (
        _coordinate(values.get("taskId"), 160),
        _agent_id(values.get("agentId")),
    )


def _task_projection(value: Any, *, default_agent_id: str | None) -> dict[str, Any]:
    source = _object(value, "Hermes scheduled task")
    task_id = _optional_coordinate(source.get("id"), 160) or _coordinate(
        source.get("job_id"), 160
    )
    raw_profile = source.get("profile") or default_agent_id
    agent_id = _agent_id(raw_profile)
    schedule = source.get("schedule")
    request = ""
    embedded_display = ""
    if isinstance(schedule, dict):
        kind = schedule.get("kind")
        if kind == "cron":
            request = _text(schedule.get("expr"), 2_048)
        elif kind == "once":
            request = _text(schedule.get("run_at"), 2_048)
        elif kind == "interval":
            minutes = _nonnegative_integer(schedule.get("minutes"), maximum=52_560_000)
            if minutes == 0:
                raise WorkspaceControlError("Hermes scheduled task interval is invalid")
            request = f"every {minutes}m"
        else:
            for key in ("expr", "run_at"):
                if schedule.get(key):
                    request = _text(schedule.get(key), 2_048)
                    break
        if schedule.get("display") is not None:
            embedded_display = _text(schedule.get("display"), 2_048, allow_empty=True)
    elif isinstance(schedule, str):
        request = _text(schedule, 2_048)
    if not request:
        raise WorkspaceControlError("Hermes scheduled task schedule is invalid")
    display = _text(
        source.get("schedule_display"), 2_048, allow_empty=True
    ) or embedded_display or request
    result: dict[str, Any] = {
        "id": task_id,
        "agentId": agent_id,
        "name": _text(source.get("name"), 240),
        "instructions": _text(source.get("prompt"), 256_000),
        "scheduleRequest": request,
        "scheduleDisplay": display,
        "delivery": _text(source.get("deliver", "local"), 512),
        "enabled": source.get("enabled") is not False,
    }
    next_run = _optional_time_value(source.get("next_run_at"))
    if next_run is not None:
        result["nextRunAt"] = next_run
    last_status = source.get("last_status")
    if last_status is not None:
        result["lastStatus"] = _text(last_status, 512, allow_empty=True)
    return result


def _optional_time_value(value: Any) -> int | str | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise WorkspaceControlError("Workspace timestamp is invalid")
    if isinstance(value, (int, float)):
        return _timestamp(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped or len(stripped.encode("utf-8")) > 64:
            raise WorkspaceControlError("Workspace timestamp is invalid")
        try:
            return _timestamp(stripped)
        except WorkspaceControlError:
            if "T" in stripped and all(ord(character) >= 32 for character in stripped):
                return stripped
    raise WorkspaceControlError("Workspace timestamp is invalid")


def _coordinate_list(value: Any, *, maximum: int, item_maximum: int) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise WorkspaceControlError("Workspace coordinate list is invalid")
    projected = [_coordinate(item, item_maximum) for item in value]
    if len(set(projected)) != len(projected):
        raise WorkspaceControlError("Workspace coordinate list is invalid")
    return projected


_EVENT_DETAIL_KEYS = frozenset(
    {
        "description",
        "summary",
        "title",
        "task_title",
        "job_title",
        "message",
        "question",
        "agent_name",
        "surface",
        "pattern_key",
        "request_id",
        "kind",
        "expires_at",
        "detail",
    }
)


_DASHBOARD_EVENT_LIMIT = 200
# Keep enough headroom for account encryption and the Loopdy Link frame
# envelope. The dashboard is a summary surface; session history remains the
# source for complete content.
_DASHBOARD_RESPONSE_MAX_BYTES = 160_000
_DASHBOARD_DETAIL_MAX_BYTES = 40_000
_COMPLETION_EVENT_TYPES = frozenset({"job.completed", "job.failed"})
_COMPLETION_SUMMARY_MAX_BYTES = 2_000


def _event_projection(
    value: Any,
    *,
    detail_maximum: int = 4_096,
    truncate_detail: bool = False,
) -> dict[str, Any]:
    source = _object(value, "Loopdy event")
    detail_source = _optional_object(source.get("detail"))
    detail: dict[str, Any] = {}
    for key in sorted(_EVENT_DETAIL_KEYS):
        raw = detail_source.get(key)
        if isinstance(raw, str):
            normalized = raw.strip()
            if normalized:
                if truncate_detail:
                    normalized = _utf8_prefix(normalized, detail_maximum)
                detail[key] = _text(normalized, detail_maximum)
    rendered = detail_source.get("generative_ui")
    if rendered is not None:
        try:
            detail["generative_ui"] = validate_rendered_envelope(rendered)
        except (GenerativeUIError, TypeError, ValueError):
            # A malformed optional card must not hide an otherwise useful
            # Inbox event. Native clients receive only renderer-validated
            # content; the invalid object remains private to the host store.
            pass
    interaction = detail_source.get("interaction")
    if interaction is not None:
        try:
            detail["interaction"] = _interaction_projection(interaction)
        except (TypeError, ValueError, WorkspaceControlError):
            # A malformed optional interaction must not hide the event.
            pass
    return {
        "eventId": _coordinate(source.get("event_id"), 220),
        "type": _coordinate(source.get("type"), 80),
        "profile": _agent_id(source.get("profile")),
        "sessionId": _optional_coordinate(source.get("session_id"), 180),
        "approvalId": _optional_coordinate(source.get("approval_id"), 180),
        "detail": detail,
        "createdAt": _timestamp(source.get("created_at")),
        "isRead": source.get("is_read") is True,
        "isPinned": source.get("is_pinned") is True,
    }


def _clarify_interaction_projection(value: Any) -> dict[str, Any]:
    source = _object(value, "Loopdy interaction")
    if set(source) != {
        "schemaVersion",
        "type",
        "requestId",
        "expiresAt",
        "allowsCustomResponse",
        "questions",
    }:
        raise WorkspaceControlError("Loopdy interaction is invalid")
    if source.get("schemaVersion") != 1 or source.get("type") != "clarify":
        raise WorkspaceControlError("Loopdy interaction is invalid")
    request_id = _coordinate(source.get("requestId"), 180)
    expires_at = source.get("expiresAt")
    if expires_at is not None:
        expires_at = _timestamp(expires_at)
    if source.get("allowsCustomResponse") is not True:
        raise WorkspaceControlError("Loopdy interaction is invalid")
    raw_questions = source.get("questions")
    if not isinstance(raw_questions, list) or not 1 <= len(raw_questions) <= 5:
        raise WorkspaceControlError("Loopdy interaction is invalid")
    questions = []
    for index, raw_question in enumerate(raw_questions):
        question = _object(raw_question, "Loopdy clarification question")
        if set(question) != {
            "id",
            "question",
            "choices",
            "multiSelect",
            "allowsCustomResponse",
        }:
            raise WorkspaceControlError("Loopdy interaction is invalid")
        choices = question.get("choices")
        if not isinstance(choices, list) or len(choices) > 4:
            raise WorkspaceControlError("Loopdy interaction is invalid")
        projected_choices = [_text(choice, 500) for choice in choices]
        if any(not choice for choice in projected_choices):
            raise WorkspaceControlError("Loopdy interaction is invalid")
        projected = {
            "id": _coordinate(question.get("id") or f"q{index}", 80),
            "question": _text(question.get("question"), 2_000),
            "choices": projected_choices,
            "multiSelect": question.get("multiSelect") is True,
            "allowsCustomResponse": question.get("allowsCustomResponse") is True,
        }
        if not projected["question"] or not projected["allowsCustomResponse"]:
            raise WorkspaceControlError("Loopdy interaction is invalid")
        questions.append(projected)
    return {
        "schemaVersion": 1,
        "type": "clarify",
        "requestId": request_id,
        "expiresAt": expires_at,
        "allowsCustomResponse": True,
        "questions": questions,
    }


def _approval_interaction_projection(value: Any) -> dict[str, Any]:
    source = _object(value, "Loopdy interaction")
    if set(source) != {
        "schemaVersion",
        "type",
        "requestId",
        "expiresAt",
        "allowedChoices",
    }:
        raise WorkspaceControlError("Loopdy interaction is invalid")
    if source.get("schemaVersion") != 1 or source.get("type") != "approval":
        raise WorkspaceControlError("Loopdy interaction is invalid")
    choices = _coordinate_list(
        source.get("allowedChoices"), maximum=4, item_maximum=16
    )
    if not set(choices).issubset({"once", "session", "always", "deny"}):
        raise WorkspaceControlError("Loopdy interaction is invalid")
    return {
        "schemaVersion": 1,
        "type": "approval",
        "requestId": _coordinate(source.get("requestId"), 180),
        "expiresAt": _timestamp(source.get("expiresAt")),
        "allowedChoices": choices,
    }


def _interaction_projection(value: Any) -> dict[str, Any]:
    source = _object(value, "Loopdy interaction")
    if source.get("type") == "clarify":
        return _clarify_interaction_projection(source)
    if source.get("type") == "approval":
        return _approval_interaction_projection(source)
    raise WorkspaceControlError("Loopdy interaction is invalid")


def _event_projection_v2(
    value: Any,
    *,
    detail_maximum: int = 4_096,
    truncate_detail: bool = False,
) -> dict[str, Any]:
    projected = _event_projection(
        value,
        detail_maximum=detail_maximum,
        truncate_detail=truncate_detail,
    )
    source = _object(value, "Loopdy event")
    if source.get("type") in _COMPLETION_EVENT_TYPES:
        projected["taskId"] = _optional_coordinate(
            source.get("task_id"), 180
        ) or _coordinate(source.get("job_id"), 180)
        detail = _object(projected["detail"], "Loopdy event detail")
        status = _optional_object(source.get("detail")).get("status")
        if status not in {"completed", "failed"}:
            raise WorkspaceControlError("Loopdy completion status is invalid")
        detail["status"] = status
    return projected


def _completion_catalog(value: Any, *, profile: str) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > 500:
        raise WorkspaceControlError("Hermes scheduled task catalog is invalid")
    catalog: dict[str, str] = {}
    for item in value:
        source = _object(item, "Hermes scheduled task")
        item_profile = source.get("profile")
        if item_profile not in {None, ""} and _agent_id(item_profile) != profile:
            raise WorkspaceControlError("Hermes scheduled task profile is invalid")
        task_id = _optional_coordinate(source.get("id"), 180) or _coordinate(
            source.get("job_id"), 180
        )
        name = _text(source.get("name"), 240)
        if task_id in catalog:
            raise WorkspaceControlError("Hermes scheduled task identity is ambiguous")
        catalog[task_id] = name
    return catalog


def _cron_job_id(session_id: str) -> str:
    match = _CRON_SESSION.fullmatch(session_id)
    return match.group(1) if match else ""


def _final_assistant_result(value: dict[str, Any]) -> str:
    rows = value.get("messages")
    if not isinstance(rows, list) or not rows or len(rows) > 500:
        raise WorkspaceControlError("Hermes session history is invalid")
    final = _object(rows[-1], "Hermes final assistant result")
    if final.get("role") != "assistant":
        raise WorkspaceControlError("Hermes final assistant result is unavailable")
    display_content = final.get("display_content")
    if isinstance(display_content, str) and display_content != "":
        content = _text(display_content, 1_000_000)
    else:
        requires_display_projection = (
            final.get("display_kind") == "hidden"
            or final.get("_compressed_summary") is True
            or final.get("compacted") is True
        )
        if requires_display_projection:
            raise WorkspaceControlError("Hermes final assistant result is unavailable")
        content = _text(final.get("content"), 1_000_000)
    summary = _utf8_prefix(content, _COMPLETION_SUMMARY_MAX_BYTES)
    if not summary:
        raise WorkspaceControlError("Hermes final assistant result is unavailable")
    return summary


def _approval_projection(value: Any, *, now: int) -> dict[str, Any]:
    source = _object(value, "Loopdy approval")
    status = _coordinate(source.get("status"), 32)
    expires_at = _timestamp(source.get("expires_at"))
    choices = _coordinate_list(
        source.get("allowed_choices"), maximum=4, item_maximum=16
    )
    if status != "pending" or expires_at <= now:
        raise WorkspaceConflictError("Approval is no longer pending")
    if not set(choices).issubset({"once", "session", "always", "deny"}):
        raise WorkspaceControlError("Approval choices are invalid")
    return {
        "id": _coordinate(source.get("approval_id"), 180),
        "requestDigest": _coordinate(source.get("request_digest"), 180),
        "eventId": _coordinate(source.get("event_id"), 220),
        "status": status,
        "allowedChoices": choices,
        "expiresAt": expires_at,
    }


class WorkspaceController:
    _HANDLERS = {
        "agents.list": "agents_list",
        "agents.create": "agents_create",
        "agents.update": "agents_update",
        "agents.avatar.get": "agents_avatar_get",
        "agents.avatar.set": "agents_avatar_set",
        "sessions.list": "sessions_list",
        "sessions.history": "sessions_history",
        "attachments.resolve": "attachments_resolve",
        "attachments.fetch": "attachments_fetch",
        "scheduled_tasks.list": "scheduled_tasks_list",
        "scheduled_tasks.delivery_targets": "scheduled_tasks_delivery_targets",
        "scheduled_tasks.create": "scheduled_tasks_create",
        "scheduled_tasks.update": "scheduled_tasks_update",
        "scheduled_tasks.delete": "scheduled_tasks_delete",
        "scheduled_tasks.pause": "scheduled_tasks_pause",
        "scheduled_tasks.resume": "scheduled_tasks_resume",
        "scheduled_tasks.run": "scheduled_tasks_run",
        "agent_defaults.get": "agent_defaults_get",
        "agent_defaults.set": "agent_defaults_set",
        "skills_tools.list": "skills_tools_list",
        "projects.list": "projects_list",
        "projects.set_active": "projects_set_active",
        "projects.create": "projects_create",
        "projects.archive": "projects_archive",
        "projects.list_directory": "projects_list_directory",
        "projects.git.capabilities": "projects_git_capabilities",
        "projects.git.status": "projects_git_status",
        "projects.git.diff": "projects_git_diff",
        "projects.git.prepare": "projects_git_prepare",
        "projects.git.execute": "projects_git_execute",
        "dashboard.load": "dashboard_load",
        "dashboard.set_event_state": "dashboard_set_event_state",
        "dashboard.dismiss_event": "dashboard_dismiss_event",
        "dashboard.dismiss_events": "dashboard_dismiss_events",
        "approvals.load": "approvals_load",
        "approvals.respond": "approvals_respond",
        "clarifications.respond": "clarifications_respond",
    }

    def __init__(self, *, backend: Any):
        self.backend = backend

    @property
    def operations(self) -> frozenset[str]:
        return frozenset(self._HANDLERS)

    async def execute(self, request: WorkspaceRequest) -> dict[str, Any]:
        handler_name = self._HANDLERS.get(request.operation)
        if handler_name is None or request.operation not in WORKSPACE_OPERATIONS:
            raise WorkspaceControlError("Unsupported Loopdy workspace operation")
        handler = getattr(self.backend, handler_name, None)
        if not callable(handler):
            raise WorkspaceControlError("Loopdy workspace operation is unavailable")
        result = handler(dict(request.payload))
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, dict):
            raise WorkspaceControlError("Loopdy workspace result is invalid")
        return result


if frozenset(WorkspaceController._HANDLERS) != WORKSPACE_OPERATIONS:
    raise RuntimeError("Loopdy workspace operations and controller handlers diverged")


__all__ = [
    "HermesWorkspaceBackend",
    "WorkspaceConflictError",
    "WorkspaceControlError",
    "WorkspaceController",
]
