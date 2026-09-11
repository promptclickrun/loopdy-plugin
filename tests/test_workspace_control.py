from __future__ import annotations

import asyncio
import base64
from contextlib import nullcontext
import hashlib
import io
import zipfile
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from loopdy_plugin.attachments import AttachmentStore
from loopdy_plugin.link_contracts import WORKSPACE_OPERATIONS, WorkspaceRequest
from loopdy_plugin.workspace_control import (
    HermesWorkspaceBackend,
    WorkspaceConflictError,
    WorkspaceControlError,
    WorkspaceController,
    _decode_skill_zip,
    _event_projection,
    _decode_skill_zip,
    _session_workspace_identity,
)


class _Backend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, name: str):
        async def invoke(payload: dict) -> dict:
            self.calls.append((name, payload))
            return {"handler": name, "accepted": True}

        return invoke


class WorkspaceControllerTests(unittest.TestCase):
    def test_scheduled_cron_bridge_uses_installed_hermes_worker_modules(self) -> None:
        from hermes_cli import web_server_cron
        from hermes_cli.web_routers import cron as cron_routes

        backend = HermesWorkspaceBackend(service=SimpleNamespace())
        listed = [{"id": "cron-job-0001"}]
        created = {"id": "cron-job-0001", "name": "Morning weather"}
        updated = {"id": "cron-job-0001", "name": "Updated weather"}

        with (
            patch.object(cron_routes, "_list_cron_jobs_sync", return_value=listed) as list_worker,
            patch.object(web_server_cron, "_create_cron_job_sync", return_value=created) as create_worker,
            patch.object(cron_routes, "_update_cron_job_sync", return_value=updated) as update_worker,
            patch.object(cron_routes, "_pause_cron_job_sync", return_value={"paused": True}) as pause_worker,
            patch.object(cron_routes, "_resume_cron_job_sync", return_value={"paused": False}) as resume_worker,
            patch.object(cron_routes, "_trigger_cron_job_sync", return_value={"ran": True}) as run_worker,
            patch.object(cron_routes, "_delete_cron_job_sync", return_value={"ok": True}) as delete_worker,
        ):
            self.assertEqual(asyncio.run(backend._cron_list("default")), listed)
            self.assertEqual(
                asyncio.run(backend._cron_create("default", {
                    "name": "Morning weather",
                    "prompt": "Summarize the weather.",
                    "schedule": "0 8 * * * America/Chicago",
                })),
                created,
            )
            self.assertEqual(
                asyncio.run(backend._cron_update(
                    "cron-job-0001", "default", {"name": "Updated weather"}
                )),
                updated,
            )
            self.assertEqual(
                asyncio.run(backend._cron_pause("cron-job-0001", "default")),
                {"paused": True},
            )
            self.assertEqual(
                asyncio.run(backend._cron_resume("cron-job-0001", "default")),
                {"paused": False},
            )
            self.assertEqual(
                asyncio.run(backend._cron_run("cron-job-0001", "default")),
                {"ran": True},
            )
            asyncio.run(backend._cron_delete("cron-job-0001", "default"))

        list_worker.assert_called_once_with("default")
        self.assertEqual(create_worker.call_args.args[1], "default")
        self.assertEqual(update_worker.call_args.args, (
            "cron-job-0001", unittest.mock.ANY, "default"
        ))
        pause_worker.assert_called_once_with("cron-job-0001", "default")
        resume_worker.assert_called_once_with("cron-job-0001", "default")
        run_worker.assert_called_once_with("cron-job-0001", "default")
        delete_worker.assert_called_once_with("cron-job-0001", "default")

    def test_session_project_identity_rejects_unbounded_folder_catalogs(self) -> None:
        catalog = {
            "projects": [{
                "id": "project-1",
                "name": "Project",
                "primary_path": "/fixture/project",
                "folders": [
                    {"path": f"/fixture/project/folder-{index}"}
                    for index in range(65)
                ],
            }]
        }

        with self.assertRaises(WorkspaceControlError):
            _session_workspace_identity("/fixture/project", catalog)

    def test_skill_zip_accepts_one_bounded_bundle(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "weather/SKILL.md",
                "---\nname: weather\ndescription: Use for weather.\n---\n\nInstructions.",
            )
            archive.writestr("weather/references/api.md", "API notes")

        name, content, supporting = _decode_skill_zip(buffer.getvalue())

        self.assertEqual(name, "weather")
        self.assertIn("description: Use for weather.", content)
        self.assertEqual(supporting, [("references/api.md", b"API notes")])

    def test_skill_zip_rejects_traversal(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "weather/SKILL.md",
                "---\nname: weather\ndescription: Use for weather.\n---\n\nInstructions.",
            )
            archive.writestr("weather/../escape.txt", "no")

        with self.assertRaisesRegex(WorkspaceControlError, "unsafe path"):
            _decode_skill_zip(buffer.getvalue())

    def test_skill_bundle_is_rescanned_after_supporting_files_are_written(self) -> None:
        async def exercise(root: Path) -> list[str]:
            from hermes_cli.web_routers import skills as skills_routes
            from tools import skill_manager_tool

            deleted: list[str] = []
            backend = HermesWorkspaceBackend(service=SimpleNamespace())
            with (
                patch.object(skills_routes, "_profile_scope", lambda _: nullcontext()),
                patch.object(skills_routes, "_clear_skills_prompt_cache", lambda: None),
                patch.object(
                    skill_manager_tool,
                    "_create_skill",
                    return_value={"success": True},
                ),
                patch.object(
                    skill_manager_tool,
                    "_find_skill",
                    return_value={"path": root},
                ),
                patch.object(
                    skill_manager_tool,
                    "_security_scan_skill",
                    return_value="blocked supporting file",
                ),
                patch.object(
                    skill_manager_tool,
                    "_delete_skill",
                    side_effect=lambda name: deleted.append(name),
                ),
            ):
                with self.assertRaisesRegex(WorkspaceControlError, "security policy rejected the skill bundle"):
                    await backend._skill_import_bundle(
                        "default",
                        "weather",
                        "---\nname: weather\ndescription: Weather.\n---\n\nInstructions.",
                        None,
                        [("scripts/fetch.py", b"print('weather')")],
                    )
            return deleted

        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(asyncio.run(exercise(Path(directory))), ["weather"])

    def test_skill_categories_match_the_hermes_single_segment_contract(self) -> None:
        from loopdy_plugin.workspace_control import _optional_skill_category

        self.assertEqual(_optional_skill_category("research.tools"), "research.tools")
        for invalid in ("Research", "research tools", "research/tools"):
            with self.subTest(invalid=invalid), self.assertRaises(WorkspaceControlError):
                _optional_skill_category(invalid)

    def test_concurrent_skill_updates_allow_only_one_revision_owner(self) -> None:
        async def exercise() -> list[object]:
            backend = HermesWorkspaceBackend(service=SimpleNamespace())
            current = {
                "content": "---\nname: weather\ndescription: Original.\n---\n\nOriginal."
            }
            update_started = asyncio.Event()
            release_update = asyncio.Event()

            async def read_skill(agent_id: str, skill_id: str) -> dict:
                return dict(current)

            async def write_skill(agent_id: str, name: str, content: str) -> None:
                update_started.set()
                await release_update.wait()
                current["content"] = content

            backend._skill_content = read_skill
            backend._skill_update = write_skill
            expected = hashlib.sha256(current["content"].encode("utf-8")).hexdigest()
            first = asyncio.create_task(backend.skills_tools_update({
                "agentId": "default",
                "skillId": "weather",
                "content": "---\nname: weather\ndescription: First.\n---\n\nFirst.",
                "expectedSha256": expected,
            }))
            await update_started.wait()
            second = asyncio.create_task(backend.skills_tools_update({
                "agentId": "default",
                "skillId": "weather",
                "content": "---\nname: weather\ndescription: Second.\n---\n\nSecond.",
                "expectedSha256": expected,
            }))
            await asyncio.sleep(0)
            release_update.set()
            return list(await asyncio.gather(first, second, return_exceptions=True))

        results = asyncio.run(exercise())

        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertEqual(
            sum(isinstance(result, WorkspaceConflictError) for result in results),
            1,
        )

    def test_every_wire_operation_has_one_explicit_backend_handler(self) -> None:
        backend = _Backend()
        controller = WorkspaceController(backend=backend)

        self.assertEqual(controller.operations, WORKSPACE_OPERATIONS)
        for index, operation in enumerate(sorted(WORKSPACE_OPERATIONS), start=1):
            request = WorkspaceRequest(
                request_id=f"workspace-operation-{index:04d}",
                operation=operation,
                payload={"sequence": index},
                sent_at=1_788_000_000 + index,
            )
            if operation.startswith("wiki."):
                # Wiki has a separate authenticated transport, never a generic
                # backend fallback when optional host support is unavailable.
                before = list(backend.calls)
                with self.assertRaises(WorkspaceControlError) as denied:
                    asyncio.run(controller.execute(request))
                self.assertEqual(denied.exception.code, "WIKI_UNAVAILABLE")
                self.assertEqual(backend.calls, before)
                continue
            result = asyncio.run(controller.execute(request))
            expected_handler = operation.replace(".", "_")
            self.assertEqual(result["handler"], expected_handler)
            self.assertEqual(backend.calls[-1], (expected_handler, {"sequence": index}))

    def test_native_groups_methods_forward_exactly_to_hermes_json_rpc(self) -> None:
        from loopdy_plugin.link_contracts import GROUPS_OPERATIONS

        backend = HermesWorkspaceBackend(service=object())
        calls: list[tuple[str, dict, str | None]] = []

        async def request(
            operation: str,
            payload: dict,
            *,
            unavailable_message: str,
            request_id: str | None = None,
        ) -> dict:
            calls.append((operation, payload, request_id))
            return {"native": operation}

        backend._hermes_request = request
        for operation in sorted(GROUPS_OPERATIONS):
            handler = getattr(backend, operation.replace(".", "_"))
            payload = {"room_id": f"room-{operation.replace('.', '-')}-0001"}
            self.assertEqual(asyncio.run(handler(payload)), {"native": operation})

        self.assertEqual([call[0] for call in calls], sorted(GROUPS_OPERATIONS))
        self.assertEqual([call[1] for call in calls], [
            {"room_id": f"room-{operation.replace('.', '-')}-0001"}
            for operation in sorted(GROUPS_OPERATIONS)
        ])
        self.assertTrue(all(call[2] == f"loopdy-{call[0]}" for call in calls))

    def test_agent_attachments_resolve_and_fetch_in_bounded_profile_scoped_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b"x" * 70_000
            image = root / "chart.png"
            image.write_bytes(content)
            backend = HermesWorkspaceBackend(
                service=object(),
                attachment_store=AttachmentStore(root / "attachments.sqlite3"),
            )

            resolved = asyncio.run(backend.attachments_resolve({
                "agentId": "default",
                "storedId": "session-1",
                "items": [{"itemId": "message-1", "text": f"Done.\nMEDIA:{image}"}],
            }))
            attachment = resolved["items"][0]["attachments"][0]
            self.assertNotIn(str(root), json.dumps(resolved))

            first = asyncio.run(backend.attachments_fetch({
                "agentId": "default",
                "attachmentId": attachment["id"],
                "offset": 0,
            }))
            second = asyncio.run(backend.attachments_fetch({
                "agentId": "default",
                "attachmentId": attachment["id"],
                "offset": first["nextOffset"],
            }))
            self.assertEqual(
                base64.b64decode(first["data"]) + base64.b64decode(second["data"]),
                content,
            )
            self.assertIsNone(second["nextOffset"])
            with self.assertRaises(WorkspaceControlError):
                asyncio.run(backend.attachments_fetch({
                    "agentId": "other",
                    "attachmentId": attachment["id"],
                    "offset": 0,
                }))

    def test_project_manager_operations_stay_inside_the_explicit_workspace_allowlist(self) -> None:
        self.assertTrue({
            "projects.list",
            "projects.set_active",
            "projects.create",
            "projects.archive",
            "projects.list_directory",
        }.issubset(WORKSPACE_OPERATIONS))

    def test_clarify_resolution_stays_inside_the_explicit_workspace_allowlist(self) -> None:
        self.assertIn("clarifications.respond", WORKSPACE_OPERATIONS)

    def test_scheduled_task_delivery_catalog_stays_inside_the_explicit_workspace_allowlist(self) -> None:
        self.assertIn("scheduled_tasks.delivery_targets", WORKSPACE_OPERATIONS)

    def test_agent_avatar_operations_stay_inside_the_explicit_workspace_allowlist(self) -> None:
        self.assertTrue({
            "agents.avatar.get",
            "agents.avatar.set",
        }.issubset(WORKSPACE_OPERATIONS))

    def test_backend_must_return_a_json_object(self) -> None:
        class _InvalidBackend:
            async def agents_list(self, payload):
                return ["not", "an", "object"]

        controller = WorkspaceController(backend=_InvalidBackend())
        request = WorkspaceRequest(
            request_id="workspace-invalid-result-0001",
            operation="agents.list",
            payload={},
            sent_at=1_788_000_001,
        )

        with self.assertRaises(WorkspaceControlError):
            asyncio.run(controller.execute(request))

    def test_model_options_uses_the_official_legacy_signature_when_explicit_filtering_is_unavailable(self) -> None:
        calls: list[dict[str, object]] = []
        hermes_cli = ModuleType("hermes_cli")
        hermes_cli.__path__ = []  # type: ignore[attr-defined]
        web_server = ModuleType("hermes_cli.web_server")

        def get_model_options(profile=None):
            calls.append({"profile": profile})
            return {
                "provider": "nous",
                "providers": [{"slug": "nous", "models": ["Hermes-4-405B"]}],
            }

        web_server.get_model_options = get_model_options
        backend = HermesWorkspaceBackend(service=object())

        with (
            patch.object(backend, "_hermes_request", side_effect=ImportError),
            patch.dict(sys.modules, {
                "hermes_cli": hermes_cli,
                "hermes_cli.web_server": web_server,
            }),
        ):
            result = asyncio.run(backend._model_options("default"))

        self.assertEqual(calls, [{"profile": "default"}])
        self.assertEqual(result["provider"], "nous")

    def test_session_messages_forwards_the_requested_offset_to_the_official_hermes_reader(self) -> None:
        calls: list[dict[str, object]] = []
        hermes_cli = ModuleType("hermes_cli")
        hermes_cli.__path__ = []  # type: ignore[attr-defined]
        web_routers = ModuleType("hermes_cli.web_routers")
        web_routers.__path__ = []  # type: ignore[attr-defined]
        sessions = ModuleType("hermes_cli.web_routers.sessions")

        async def get_session_messages(session_id, **kwargs):
            calls.append({"session_id": session_id, **kwargs})
            return {"messages": []}

        sessions.get_session_messages = get_session_messages
        backend = HermesWorkspaceBackend(service=object())

        with patch.dict(sys.modules, {
            "hermes_cli": hermes_cli,
            "hermes_cli.web_routers": web_routers,
            "hermes_cli.web_routers.sessions": sessions,
        }):
            result = asyncio.run(backend._session_messages(
                "stored-session-0001",
                "default",
                include_compacted=True,
                offset=37,
            ))

        self.assertEqual(result, {"messages": []})
        self.assertEqual(calls, [{
            "session_id": "stored-session-0001",
            "profile": "default",
            "limit": 500,
            "offset": 37,
            "order": "latest",
            "include_compacted": True,
        }])


class _ProfileBackend(HermesWorkspaceBackend):
    def __init__(
        self,
        *,
        session_workspace_setter=None,
        session_workspace_getter=None,
    ) -> None:
        super().__init__(
            service=object(),
            session_workspace_setter=session_workspace_setter,
            session_workspace_getter=session_workspace_getter,
        )
        self.saved_config = None
        self.session_updates = []
        self.session_deletes = []

    async def _profile_records(self):
        return [
            {
                "id": "default",
                "display_name": "Gordie",
                "description": "Primary household agent",
                "is_default": True,
            },
            {
                "id": "research",
                "display_name": "",
                "description": "Research specialist",
                "is_default": False,
            },
        ]

    async def _profile_soul(self, agent_id):
        return {
            "default": "Be useful and concise.",
            "research": "Cite primary sources.",
        }[agent_id]

    async def _profile_config(self, agent_id):
        self.loaded_agent_id = agent_id
        return {
            "model": {"provider": "nous", "default": "Hermes-4-405B"},
            "agent": {"reasoning_effort": "high"},
            "delegation": {
                "provider": "openai",
                "model": "gpt-5.6",
                "reasoning_effort": "medium",
            },
            "cron": {"model_provider": "anthropic", "model": "claude-opus-4.1"},
            "platforms": {
                "loopdy": {
                    "extra": {
                        "agent_defaults": {
                            "scheduled_tasks": {"reasoning_effort": "low"}
                        }
                    }
                }
            },
        }

    async def _model_options(self, agent_id):
        return {
            "provider": "nous",
            "providers": [
                {
                    "slug": "nous",
                    "name": "Nous Research",
                    "models": ["Hermes-4-405B"],
                    "api_key": "must-never-cross-link",
                },
                {
                    "slug": "openai",
                    "name": "OpenAI",
                    "models": ["gpt-5.6"],
                    "is_user_defined": True,
                },
            ],
        }

    async def _save_profile_config(self, agent_id, config):
        self.saved_config = (agent_id, config)

    async def _update_profile(
        self,
        *,
        agent_id,
        display_name,
        description,
        instructions=None,
        expected_instructions_sha256=None,
    ):
        # This fixture must never fall through to Hermes' live profile writer.
        # A prior test did exactly that and replaced the developer's real
        # default SOUL.md with the fixture string below.
        self.updated_profile = {
            "agent_id": agent_id,
            "display_name": display_name,
            "description": description,
            "instructions": instructions,
            "expected_instructions_sha256": expected_instructions_sha256,
        }

    async def _set_profile_avatar(self, agent_id, avatar):
        self.saved_avatar = (agent_id, avatar)

    async def _profile_avatar(self, agent_id):
        return {"found": getattr(self, "avatar_is_present", False)}

    async def _skills_catalog(self, agent_id):
        self.skills_agent_id = agent_id
        return [
            {
                "name": "weather",
                "description": "Look up current conditions.",
                "category": "Research",
                "enabled": True,
                "path": "/private/profile/skills/weather/SKILL.md",
            }
        ]

    async def _plugins_catalog(self, agent_id="default"):
        return [
            {
                "key": "loopdy",
                "name": "Loopdy",
                "kind": "platform",
                "version": "0.8.0",
                "description": "Secure Loopdy Link channel.",
                "source": "/private/plugins/loopdy",
                "enabled": True,
                "tools": 2,
                "hooks": 1,
                "middleware": 0,
                "commands": 3,
                "error": "must never cross link",
            }
        ]

    async def _mcp_catalog(self, agent_id):
        self.mcp_agent_id = agent_id
        return {
            "servers": [
                {
                    "name": "calendar",
                    "transport": "http",
                    "url": "https://private.example.invalid/mcp",
                    "command": "must never cross link",
                    "args": ["--secret"],
                    "env": {"TOKEN": "secret"},
                    "auth": {"token": "secret"},
                    "enabled": True,
                    "tools": ["events_list", "events_create"],
                },
                {
                    "name": "search",
                    "transport": "stdio",
                    "command": "must never cross link",
                    "enabled": True,
                    "tools": {"exclude": ["private_tool_name"]},
                }
            ]
        }

    async def _projects_catalog(self, agent_id):
        self.project_catalog_agent_ids = getattr(
            self, "project_catalog_agent_ids", []
        ) + [agent_id]
        return {
            "active_id": "project-home",
            "projects": [
                {
                    "id": "project-home",
                    "name": "Home",
                    "description": "Household workspace",
                    "archived": False,
                    "primary_path": "/Users/private/home",
                    "folders": [
                        {"path": "/Users/private/home", "label": "Home"},
                        {"path": "/Users/private/notes", "label": "Notes"},
                    ],
                }
            ],
        }

    async def _set_active_project(self, agent_id, project_id):
        self.selected_project = (agent_id, project_id)
        return "/Users/private/home"

    async def _project_directory(self, agent_id, project_id):
        return "/Users/private/home"

    async def _create_project(self, agent_id, name, folder_path):
        self.created_project = (agent_id, name, folder_path)

    async def _archive_project(self, agent_id, project_id):
        self.archived_project = (agent_id, project_id)

    async def _session_catalog(self, agent_id):
        self.session_agent_id = agent_id
        return {
            "sessions": [
                {
                    "id": "stored-session-0001",
                    "profile": "default",
                    "source": "loopdy",
                    "chat_id": "visible-session-0001",
                    "title": "Weather follow-up",
                    "preview": "Check tomorrow too.",
                    "message_count": 4,
                    "started_at": 1_788_000_000,
                    "last_active": 1_788_000_100,
                    "pinned": True,
                    "system_prompt": "must never cross link",
                }
            ]
        }

    async def _session_update(self, session_id, body):
        self.session_updates.append((session_id, body))
        return {"ok": True}

    async def _session_delete(self, session_id, agent_id):
        self.session_deletes.append((session_id, agent_id))
        return {"ok": True}

    async def _session_messages(
        self, stored_id, agent_id, *, include_compacted=False
    ):
        self.history_include_compacted = include_compacted
        self.history_coordinate = (stored_id, agent_id)
        return {
            "messages": [
                {"id": 1, "role": "user", "content": "What is the weather?"},
                {
                    "id": 2,
                    "role": "assistant",
                    "content": "It is sunny.",
                    "reasoning_content": "Checked the forecast.",
                    "tool_calls": [
                        {
                            "id": "weather-call-1",
                            "function": {
                                "name": "weather",
                                "arguments": "{\"city\":\"Chicago\"}",
                            },
                        }
                    ],
                    "display_metadata": {
                        "activity_id": "activity-1",
                        "subagent_id": "forecast-agent",
                        "bot_handoff": "forecast-agent",
                    },
                },
                {
                    "id": 3,
                    "role": "tool",
                    "content": "Forecast returned.",
                    "tool_name": "weather",
                    "tool_call_id": "weather-call-1",
                    "display_metadata": {
                        "activity_id": "activity-1",
                        "subagent_id": "forecast-agent",
                        "bot_handoff": {
                            "from": "gordie",
                            "to": "forecast-agent",
                        },
                    },
                },
                {"id": 4, "role": "", "content": "must not leak"},
                {"id": 5, "role": {"invalid": True}, "content": "must not leak"},
            ]
        }

    async def _cron_list(self, agent_id):
        self.cron_list_agent = agent_id
        return [self._job()]

    async def _cron_delivery_targets(self):
        return [
            {
                "id": "loopdy",
                "name": "Loopdy",
                "home_target_set": True,
                "home_env_var": "MUST_NOT_CROSS_LINK",
            },
            {
                "id": "slack",
                "name": "Slack",
                "home_target_set": False,
                "home_env_var": "MUST_NOT_CROSS_LINK",
            },
            {
                "id": "bot-chat:research",
                "name": "Bot Chat (research)",
                "home_target_set": True,
                "home_env_var": None,
            },
        ]

    async def _cron_create(self, agent_id, values):
        self.cron_created = (agent_id, values)
        self.cron_delivery = values["deliver"]
        return {**self._job(), "deliver": self.cron_delivery}

    async def _cron_update(self, job_id, agent_id, updates):
        self.cron_updated = (job_id, agent_id, updates)
        self.cron_delivery = updates.get("deliver", getattr(self, "cron_delivery", "loopdy"))
        return {**self._job(), "deliver": self.cron_delivery}

    async def _cron_pause(self, job_id, agent_id):
        self.cron_action = ("pause", job_id, agent_id)
        return {**self._job(), "enabled": False}

    async def _cron_resume(self, job_id, agent_id):
        self.cron_action = ("resume", job_id, agent_id)
        return self._job()

    async def _cron_run(self, job_id, agent_id):
        self.cron_action = ("run", job_id, agent_id)
        return {**self._job(), "last_status": "completed"}

    async def _cron_delete(self, job_id, agent_id):
        self.cron_action = ("delete", job_id, agent_id)

    @staticmethod
    def _job():
        return {
            "id": "cron-job-0001",
            "profile": "default",
            "name": "Morning weather",
            "prompt": "Summarize the weather.",
            "schedule": {"kind": "cron", "expr": "0 8 * * *", "display": "Every day at 8:00 AM"},
            "schedule_display": "Every day at 8:00 AM",
            "next_run_at": 1_788_086_400,
            "enabled": True,
            "last_status": "success",
            "deliver": "loopdy",
            "base_url": "https://private.invalid",
            "script": "/private/task.py",
        }


class _NormalizedHermesProfileBackend(HermesWorkspaceBackend):
    """The shape returned by the current Hermes config/model services."""

    def __init__(self) -> None:
        super().__init__(service=object())

    async def _profile_config(self, agent_id):
        return {
            "model": "gpt-5.6-sol",
            "agent": {"reasoning_effort": "high"},
            "delegation": {},
            "cron": {},
        }

    async def _model_options(self, agent_id):
        return {
            "provider": "openai-codex",
            "providers": [
                {
                    "slug": "moa",
                    "name": "Mixture of Agents",
                    "models": ["Frontier Tuned", "Small Stuff"],
                },
                {
                    "slug": "openai-codex",
                    "name": "OpenAI Codex",
                    "models": ["gpt-5.6-sol"],
                },
            ],
        }


class _VisibleIdHistoryBackend(_ProfileBackend):
    async def _session_messages(
        self, stored_id, agent_id, *, include_compacted=False
    ):
        if stored_id == "visible-session-0001":
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Session not found")
        return await super()._session_messages(
            stored_id,
            agent_id,
            include_compacted=include_compacted,
        )


class _CompactedHistoryBackend(_ProfileBackend):
    async def _session_messages(
        self, stored_id, agent_id, *, include_compacted=False
    ):
        self.history_include_compacted = include_compacted
        return {
            "messages": [
                {"id": 1, "role": "user", "content": "Earlier question."},
                {"id": 2, "role": "assistant", "content": "Earlier answer."},
                {
                    "id": 3,
                    "role": "assistant",
                    "content": "Compaction summary.",
                    "display_content": None,
                    "compacted": True,
                },
            ]
        }


class _EmptyDisplayContentHistoryBackend(_ProfileBackend):
    async def _session_messages(
        self, stored_id, agent_id, *, include_compacted=False
    ):
        return {
            "messages": [
                {
                    "id": 1,
                    "role": "user",
                    "content": "What is the weather?",
                    "display_content": "",
                },
                {
                    "id": 2,
                    "role": "assistant",
                    "content": "It is sunny.",
                    "display_content": "",
                },
            ]
        }


class _PagedHistoryBackend(_ProfileBackend):
    def __init__(self) -> None:
        super().__init__()
        self.history_offsets: list[int] = []

    async def _session_messages(
        self,
        stored_id,
        agent_id,
        *,
        include_compacted=False,
        offset=0,
    ):
        self.history_offsets.append(offset)
        rows = [
            {"id": index, "role": "assistant", "content": character * 80_000}
            for index, character in enumerate(("a", "b", "c"), start=1)
        ]
        remaining = rows[:max(0, len(rows) - offset)]
        return {"messages": remaining[-500:]}


class HermesWorkspaceBackendTests(unittest.TestCase):
    def test_project_git_status_requires_the_session_project_before_git_io(self) -> None:
        class ProjectBackend(HermesWorkspaceBackend):
            async def _projects_catalog(self, agent_id):
                return {
                    "active_id": "project-loopdy",
                    "projects": [
                        {
                            "id": "project-loopdy",
                            "name": "Loopdy",
                            "archived": False,
                            "primary_path": "/fixture/loopdy",
                            "folders": [
                                {
                                    "path": "/fixture/loopdy",
                                    "label": "Loopdy",
                                    "is_primary": True,
                                }
                            ],
                        }
                    ],
                }

        class Git:
            def __init__(self):
                self.calls = []

            def status(self, workspace_id):
                self.calls.append(("status", workspace_id))
                return {
                    "workspace_id": workspace_id,
                    "status_token": "sha256:" + "a" * 64,
                    "head": {
                        "oid": "abc123",
                        "branch": "main",
                        "detached": False,
                        "upstream": None,
                        "ahead": 0,
                        "behind": 0,
                    },
                    "files": [],
                    "files_page": {"total": 0, "returned": 0, "truncated": False},
                    "staged": {"files": 0, "insertions": 0, "deletions": 0},
                    "changes": {"files": 0, "insertions": 0, "deletions": 0},
                    "conflicts": [],
                    "conflicts_page": {"total": 0, "returned": 0, "truncated": False},
                    "dirty": False,
                }

        git = Git()
        session_paths = {
            "session_fixture_0001": "/fixture/loopdy",
            "session_other_0001": "/fixture/other",
        }
        backend = ProjectBackend(
            service=object(),
            workspace_git=git,
            session_workspace_getter=lambda agent_id, session_id: session_paths[session_id],
            connection_id_getter=lambda: "verified-link-connection-0001",
        )
        request = {
            "agentId": "default",
            "sessionId": "session_fixture_0001",
            "workspaceId": "project-loopdy",
        }

        status = asyncio.run(backend.projects_git_status(request))

        self.assertEqual(status["workspaceId"], "project-loopdy")
        self.assertEqual(status["statusToken"], "sha256:" + "a" * 64)
        self.assertEqual(git.calls, [("status", "project-loopdy")])

        with self.assertRaisesRegex(WorkspaceControlError, "session is not anchored"):
            asyncio.run(
                backend.projects_git_status(
                    {**request, "sessionId": "session_other_0001"}
                )
            )
        self.assertEqual(git.calls, [("status", "project-loopdy")])

    def test_project_git_methods_forward_only_fixed_fields_and_connection_identity(self) -> None:
        class ProjectBackend(HermesWorkspaceBackend):
            async def _projects_catalog(self, agent_id):
                return {
                    "active_id": "project-loopdy",
                    "projects": [
                        {
                            "id": "project-loopdy",
                            "name": "Loopdy",
                            "archived": False,
                            "primary_path": "/fixture/loopdy",
                            "folders": [{"path": "/fixture/loopdy", "is_primary": True}],
                        }
                    ],
                }

        class Git:
            def __init__(self):
                self.calls = []

            def capabilities(self):
                self.calls.append(("capabilities",))
                return {
                    "schema_version": 1,
                    "capabilities": {
                        "status": True,
                        "stage": True,
                        "commit": True,
                        "push": True,
                        "fetch": True,
                        "pull": True,
                        "arbitrary_command": False,
                    },
                    "workspaces": [
                        {
                            "workspace_id": "project-loopdy",
                            "label": "Loopdy",
                            "visibility": "private",
                            "operations": ["commit", "fetch", "pull", "push", "stage", "status"],
                            "remotes": ["origin"],
                            "branches": ["main"],
                            "mutations_enabled": True,
                        }
                    ],
                }

            def diff(self, workspace_id, **kwargs):
                self.calls.append(("diff", workspace_id, kwargs))
                return {
                    "path": kwargs["path"],
                    "side": kwargs["side"],
                    "availability": "available",
                    "offset": kwargs["offset"],
                    "lines": [],
                    "next_offset": None,
                }

            def prepare(self, **kwargs):
                self.calls.append(("prepare", kwargs))
                return {
                    "confirmation_token": "confirmation_coordinate_0001",
                    "operation_digest": "sha256:" + "b" * 64,
                    "expires_at": "2026-08-31T12:00:00Z",
                    "preview": {"summary": "Stage 1 selected path(s)", "paths": ["tracked.txt"]},
                }

            def execute(self, operation, request, *, connection_id):
                self.calls.append(("execute", operation, request, connection_id))
                return {
                    "operation_id": request["idempotency_key"],
                    "workspace_id": request["workspace_id"],
                    "operation": operation,
                    "result": {"mode": "stage", "paths": ["tracked.txt"]},
                    "status": {"workspace_id": request["workspace_id"], "dirty": True},
                }

        git = Git()
        backend = ProjectBackend(
            service=object(),
            workspace_git=git,
            session_workspace_getter=lambda _agent, _session: "/fixture/loopdy",
            connection_id_getter=lambda: "verified-link-connection-0001",
        )
        base = {
            "agentId": "default",
            "sessionId": "session_fixture_0001",
            "workspaceId": "project-loopdy",
        }
        status_token = "sha256:" + "a" * 64

        capabilities = asyncio.run(backend.projects_git_capabilities(base))
        diff = asyncio.run(
            backend.projects_git_diff(
                {
                    **base,
                    "path": "tracked.txt",
                    "side": "worktree",
                    "statusToken": status_token,
                    "offset": 0,
                    "limit": 200,
                }
            )
        )
        prepared = asyncio.run(
            backend.projects_git_prepare(
                {
                    **base,
                    "operation": "stage",
                    "statusToken": status_token,
                    "input": {"mode": "stage", "paths": ["tracked.txt"]},
                }
            )
        )
        executed = asyncio.run(
            backend.projects_git_execute(
                {
                    **base,
                    "operation": "stage",
                    "statusToken": status_token,
                    "input": {"mode": "stage", "paths": ["tracked.txt"]},
                    "confirmationToken": "confirmation_coordinate_0001",
                    "idempotencyKey": "12345678-1234-4234-8234-123456789abc",
                }
            )
        )

        self.assertEqual(capabilities["workspaces"][0]["workspaceId"], "project-loopdy")
        self.assertEqual(diff["nextOffset"], None)
        self.assertEqual(prepared["confirmationToken"], "confirmation_coordinate_0001")
        self.assertEqual(executed["operationId"], "12345678-1234-4234-8234-123456789abc")
        self.assertIn(
            (
                "prepare",
                {
                    "workspace_id": "project-loopdy",
                    "operation": "stage",
                    "input_": {"mode": "stage", "paths": ["tracked.txt"]},
                    "expected_status_token": status_token,
                    "connection_id": "verified-link-connection-0001",
                },
            ),
            git.calls,
        )
        self.assertIn(
            (
                "execute",
                "stage",
                {
                    "workspace_id": "project-loopdy",
                    "expected_status_token": status_token,
                    "confirmation_token": "confirmation_coordinate_0001",
                    "idempotency_key": "12345678-1234-4234-8234-123456789abc",
                    "mode": "stage",
                    "paths": ["tracked.txt"],
                },
                "verified-link-connection-0001",
            ),
            git.calls,
        )

    def test_project_git_errors_are_bounded_and_never_project_host_details(self) -> None:
        from loopdy_plugin.workspace_git import WorkspaceGitError

        class ProjectBackend(HermesWorkspaceBackend):
            async def _projects_catalog(self, agent_id):
                return {
                    "projects": [
                        {
                            "id": "project-loopdy",
                            "name": "Loopdy",
                            "archived": False,
                            "primary_path": "/fixture/loopdy",
                            "folders": [],
                        }
                    ]
                }

        class Git:
            def status(self, workspace_id):
                raise WorkspaceGitError(
                    "SECRET_SCAN_BLOCKED",
                    "blocked /private/project/.env https://secret.invalid token=private",
                    details={"path": "/private/project/.env", "credential": "private"},
                )

        backend = ProjectBackend(
            service=object(),
            workspace_git=Git(),
            session_workspace_getter=lambda _agent, _session: "/fixture/loopdy",
            connection_id_getter=lambda: "verified-link-connection-0001",
        )

        with self.assertRaises(WorkspaceControlError) as raised:
            asyncio.run(
                backend.projects_git_status(
                    {
                        "agentId": "default",
                        "sessionId": "session_fixture_0001",
                        "workspaceId": "project-loopdy",
                    }
                )
            )

        self.assertEqual(raised.exception.code, "sensitive_data_blocked")
        self.assertEqual(raised.exception.status, "failed")
        projected = str(raised.exception).lower()
        self.assertNotIn("/private", projected)
        self.assertNotIn("https://", projected)
        self.assertNotIn("token", projected)

    def test_project_git_errors_preserve_fixed_recovery_codes(self) -> None:
        from loopdy_plugin.workspace_git import WorkspaceGitError

        class ProjectBackend(HermesWorkspaceBackend):
            async def _projects_catalog(self, agent_id):
                return {
                    "projects": [
                        {
                            "id": "project-loopdy",
                            "name": "Loopdy",
                            "archived": False,
                            "primary_path": "/fixture/loopdy",
                            "folders": [],
                        }
                    ]
                }

        class Git:
            code = ""

            def status(self, workspace_id):
                raise WorkspaceGitError(self.code, "private host detail")

        git = Git()
        backend = ProjectBackend(
            service=object(),
            workspace_git=git,
            session_workspace_getter=lambda _agent, _session: "/fixture/loopdy",
            connection_id_getter=lambda: "verified-link-connection-0001",
        )
        request = {
            "agentId": "default",
            "sessionId": "session_fixture_0001",
            "workspaceId": "project-loopdy",
        }
        expected = {
            "WORKTREE_CONFLICTED": "worktree_conflicted",
            "NON_FAST_FORWARD": "non_fast_forward",
            "GIT_TIMEOUT": "git_timeout",
        }

        for host_code, wire_code in expected.items():
            git.code = host_code
            with self.assertRaises(WorkspaceControlError) as raised:
                asyncio.run(backend.projects_git_status(request))
            self.assertEqual(raised.exception.code, wire_code)
            self.assertNotIn("private host detail", str(raised.exception))

    def test_project_git_capabilities_are_scoped_to_the_requested_project(self) -> None:
        class ProjectBackend(HermesWorkspaceBackend):
            async def _projects_catalog(self, agent_id):
                return {
                    "projects": [
                        {
                            "id": "project-loopdy",
                            "name": "Loopdy",
                            "archived": False,
                            "primary_path": "/fixture/loopdy",
                            "folders": [],
                        }
                    ]
                }

        class Git:
            def capabilities(self):
                return {
                    "schema_version": 1,
                    "capabilities": {
                        "status": True,
                        "stage": True,
                        "commit": True,
                        "push": True,
                        "fetch": True,
                        "pull": True,
                        "arbitrary_command": False,
                    },
                    "workspaces": [
                        {
                            "workspace_id": "project-loopdy",
                            "label": "Loopdy",
                            "visibility": "private",
                            "operations": ["status"],
                            "remotes": [],
                            "branches": [],
                            "mutations_enabled": False,
                        },
                        {
                            "workspace_id": "another-project",
                            "label": "Other",
                            "visibility": "private",
                            "operations": ["status", "stage", "commit", "push", "fetch", "pull"],
                            "remotes": ["origin"],
                            "branches": ["main"],
                            "mutations_enabled": True,
                        },
                    ],
                }

        backend = ProjectBackend(
            service=object(),
            workspace_git=Git(),
            session_workspace_getter=lambda _agent, _session: "/fixture/loopdy",
            connection_id_getter=lambda: "verified-link-connection-0001",
        )

        result = asyncio.run(
            backend.projects_git_capabilities(
                {
                    "agentId": "default",
                    "sessionId": "session_fixture_0001",
                    "workspaceId": "project-loopdy",
                }
            )
        )

        self.assertEqual(
            result["capabilities"],
            {
                "status": True,
                "stage": False,
                "commit": False,
                "push": False,
                "fetch": False,
                "pull": False,
                "arbitraryCommand": False,
            },
        )
        self.assertEqual(
            [row["workspaceId"] for row in result["workspaces"]],
            ["project-loopdy"],
        )

    def test_non_git_hermes_project_is_a_bounded_capability_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = str(Path(directory).resolve())

            class ProjectBackend(HermesWorkspaceBackend):
                async def _projects_catalog(self, agent_id):
                    return {
                        "projects": [
                            {
                                "id": "project-not-git",
                                "name": "Notes",
                                "archived": False,
                                "primary_path": root,
                                "folders": [],
                            }
                        ]
                    }

            backend = ProjectBackend(
                service=object(),
                session_workspace_getter=lambda _agent, _session: root,
                connection_id_getter=lambda: "verified-link-connection-0001",
                workspace_git_state_path=Path(directory) / "git-state.sqlite3",
            )

            with self.assertRaises(WorkspaceControlError) as raised:
                asyncio.run(
                    backend.projects_git_capabilities(
                        {
                            "agentId": "default",
                            "sessionId": "session_fixture_0001",
                            "workspaceId": "project-not-git",
                        }
                    )
                )

        self.assertEqual(raised.exception.code, "project_not_repository")
        self.assertEqual(
            str(raised.exception), "This Project is not a Git repository."
        )

    def test_registered_hermes_project_defaults_to_read_only_git_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            subprocess.run(
                ["git", "init", "-b", "main"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            (root / "untracked.txt").write_text("project change\n", encoding="utf-8")

            class ProjectBackend(HermesWorkspaceBackend):
                async def _projects_catalog(self, agent_id):
                    return {
                        "projects": [
                            {
                                "id": "project-loopdy",
                                "name": "Loopdy",
                                "archived": False,
                                "primary_path": str(root),
                                "folders": [],
                            }
                        ]
                    }

            backend = ProjectBackend(
                service=object(),
                session_workspace_getter=lambda _agent, _session: str(root),
                connection_id_getter=lambda: "verified-link-connection-0001",
                workspace_git_state_path=Path(directory) / "git-state.sqlite3",
            )
            request = {
                "agentId": "default",
                "sessionId": "session_fixture_0001",
                "workspaceId": "project-loopdy",
            }

            with patch.dict(os.environ, {"LOOPDY_WORKSPACE_GIT_CONFIG": ""}):
                capabilities = asyncio.run(backend.projects_git_capabilities(request))
                status = asyncio.run(backend.projects_git_status(request))

        self.assertTrue(capabilities["capabilities"]["status"])
        self.assertFalse(capabilities["capabilities"]["stage"])
        self.assertFalse(capabilities["workspaces"][0]["mutationsEnabled"])
        self.assertEqual(status["changes"]["files"], 1)
        self.assertEqual(status["files"][0]["path"], "untracked.txt")

    @unittest.skipUnless(sys.platform == "darwin", "macOS filesystem path behavior")
    def test_project_git_accepts_case_variant_paths_to_the_same_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            subprocess.run(
                ["git", "init", "-b", "main"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            (root / "untracked.txt").write_text("project change\n", encoding="utf-8")
            variant = root.with_name("REPO")
            if not variant.exists() or not variant.samefile(root):
                self.skipTest("case-sensitive filesystem")

            class ProjectBackend(HermesWorkspaceBackend):
                async def _projects_catalog(self, agent_id):
                    return {
                        "projects": [
                            {
                                "id": "project-loopdy",
                                "name": "Loopdy",
                                "archived": False,
                                "primary_path": str(variant),
                                "folders": [],
                            }
                        ]
                    }

            backend = ProjectBackend(
                service=object(),
                session_workspace_getter=lambda _agent, _session: str(root),
                connection_id_getter=lambda: "verified-link-connection-0001",
                workspace_git_state_path=Path(directory) / "git-state.sqlite3",
            )

            status = asyncio.run(backend.projects_git_status({
                "agentId": "default",
                "sessionId": "session_fixture_0001",
                "workspaceId": "project-loopdy",
            }))

        self.assertEqual(status["changes"]["files"], 1)
        self.assertEqual(status["files"][0]["path"], "untracked.txt")

    def test_capability_catalog_uses_profile_and_strips_private_configuration(self) -> None:
        backend = _ProfileBackend()

        with patch("loopdy_plugin.workspace_capabilities.toolsets", return_value=[]):
            result = asyncio.run(backend.skills_tools_list({"agentId": "default"}))

        self.assertEqual(backend.skills_agent_id, "default")
        self.assertEqual(backend.mcp_agent_id, "default")
        self.assertEqual(set(result["management"]), {"version", "read", "create", "update", "import"})
        self.assertEqual(result["management"]["version"], 2)
        self.assertEqual(result["tools"], [])
        self.assertEqual({key: result[key] for key in ("agentId", "skills", "plugins", "mcpServers")}, {
            "agentId": "default",
            "skills": [{
                "id": "weather",
                "name": "weather",
                "description": "Look up current conditions.",
                "category": "Research",
                "enabled": True,
            }],
            "plugins": [{
                "id": "loopdy",
                "name": "Loopdy",
                "kind": "platform",
                "version": "0.8.0",
                "description": "Secure Loopdy Link channel.",
                "enabled": True,
                "capabilityCount": 6,
                "controlReason": "",
            }],
            "mcpServers": [{
                "id": "calendar",
                "name": "calendar",
                "transport": "http",
                "enabled": True,
                "toolCount": 2,
            }, {
                "id": "search",
                "name": "search",
                "transport": "stdio",
                "enabled": True,
                "toolCount": None,
            }],
        })
        serialized = repr(result).lower()
        for private_value in ("private", "secret", "command", "args", "env", "auth", "source", "url"):
            self.assertNotIn(private_value, serialized)

    def test_workspace_catalog_projects_only_safe_metadata_and_selects_exact_id(self) -> None:
        backend = _ProfileBackend()

        listed = asyncio.run(backend.projects_list({"agentId": "default"}))
        selected = asyncio.run(backend.projects_set_active({
            "agentId": "default",
            "workspaceId": "project-home",
        }))

        self.assertEqual(listed, {
            "activeWorkspaceId": "project-home",
            "workspaces": [{
                "id": "project-home",
                "name": "Home",
                "description": "Household workspace",
                "folderCount": 2,
                "isActive": True,
            }],
        })
        self.assertEqual(backend.selected_project, ("default", "project-home"))
        self.assertEqual(
            backend.project_catalog_agent_ids,
            ["default", "default", "default"],
        )
        self.assertEqual(selected, listed)
        self.assertNotIn("/users", repr(listed).lower())

    def test_chat_workspace_selection_reanchors_only_the_calling_session(self) -> None:
        anchored = []

        async def anchor(agent_id, session_id, path):
            anchored.append((agent_id, session_id, path))

        backend = _ProfileBackend(session_workspace_setter=anchor)

        selected = asyncio.run(backend.projects_set_active({
            "agentId": "default",
            "workspaceId": "project-home",
            "sessionId": "loopdy-chat-0001",
        }))

        self.assertEqual(selected["activeWorkspaceId"], "project-home")
        self.assertEqual(anchored, [(
            "default",
            "loopdy-chat-0001",
            "/Users/private/home",
        )])

        asyncio.run(backend.projects_set_active({
            "agentId": "default",
            "workspaceId": "project-home",
        }))
        self.assertEqual(len(anchored), 1)

    def test_workspace_catalog_resolves_the_project_anchored_to_the_calling_session(self) -> None:
        backend = _ProfileBackend(
            session_workspace_getter=lambda agent_id, session_id: (
                "/Users/private/home"
                if (agent_id, session_id) == ("default", "loopdy-chat-0001")
                else None
            )
        )

        listed = asyncio.run(backend.projects_list({
            "agentId": "default",
            "sessionId": "loopdy-chat-0001",
        }))

        self.assertEqual(listed["sessionWorkspaceId"], "project-home")
        self.assertNotIn("/Users/private", repr(listed))

    def test_workspace_manager_creates_and_archives_through_hermes_project_helpers(self) -> None:
        backend = _ProfileBackend()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory).resolve()
            created = asyncio.run(backend.projects_create({
                "agentId": "default",
                "name": "Loopdy Native",
                "folderPath": str(folder),
            }))
            archived = asyncio.run(backend.projects_archive({
                "agentId": "default",
                "workspaceId": "project-home",
            }))

        self.assertEqual(backend.created_project, (
            "default",
            "Loopdy Native",
            str(folder),
        ))
        self.assertEqual(backend.archived_project, ("default", "project-home"))
        self.assertEqual(created["activeWorkspaceId"], "project-home")
        self.assertEqual(archived["workspaces"][0]["id"], "project-home")

    def test_directory_suggestions_are_bounded_directories_only_and_do_not_follow_symlinks(self) -> None:
        backend = HermesWorkspaceBackend(service=object())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent"
            outside = root / "outside"
            parent.mkdir()
            outside.mkdir()
            (parent / "alpha").mkdir()
            (parent / "alpine").mkdir()
            (parent / "artifact.txt").write_text("must never cross Link")
            (parent / "alias").symlink_to(outside, target_is_directory=True)

            first = asyncio.run(backend.projects_list_directory({
                "agentId": "default",
                "parentPath": str(parent),
                "prefix": "al",
                "offset": 0,
                "limit": 1,
            }))
            second = asyncio.run(backend.projects_list_directory({
                "agentId": "default",
                "parentPath": str(parent),
                "prefix": "al",
                "offset": 1,
                "limit": 1,
            }))

            self.assertEqual(first, {
                "parentPath": str(parent.resolve()),
                "folders": [{
                    "name": "alpha",
                    "path": str((parent / "alpha").resolve()),
                }],
                "nextOffset": 1,
            })
            self.assertEqual(second["folders"], [{
                "name": "alpine",
                "path": str((parent / "alpine").resolve()),
            }])
            self.assertIsNone(second["nextOffset"])
            self.assertNotIn("artifact.txt", repr(first) + repr(second))
            self.assertNotIn("alias", repr(first) + repr(second))
            self.assertNotIn("must never cross Link", repr(first) + repr(second))

            for invalid in (str(parent / ".."), str(parent) + "\u0000escape"):
                with self.assertRaises(WorkspaceControlError):
                    asyncio.run(backend.projects_list_directory({
                        "agentId": "default",
                        "parentPath": invalid,
                        "prefix": "",
                        "offset": 0,
                        "limit": 20,
                    }))

    def test_workspace_catalog_rejects_unknown_or_extra_selection_coordinates(self) -> None:
        backend = _ProfileBackend()

        with self.assertRaises(WorkspaceControlError):
            asyncio.run(backend.projects_set_active({
                "agentId": "default",
                "workspaceId": "missing",
            }))
        with self.assertRaises(WorkspaceControlError):
            asyncio.run(backend.projects_set_active({
                "agentId": "default",
                "workspaceId": "project-home",
                "path": "/private",
            }))

    def test_workspace_selection_does_not_change_active_project_when_session_move_fails(self) -> None:
        async def fail_move(_agent_id, _session_id, _path):
            raise WorkspaceControlError("Session move failed")

        backend = _ProfileBackend()
        backend.session_workspace_setter = fail_move

        with self.assertRaisesRegex(WorkspaceControlError, "Session move failed"):
            asyncio.run(backend.projects_set_active({
                "agentId": "default",
                "workspaceId": "project-home",
                "sessionId": "session-fixture-0001",
            }))

        self.assertFalse(hasattr(backend, "selected_project"))

    def test_workspace_catalog_isolated_by_agent_profile(self) -> None:
        from hermes_cli import projects_db

        backend = HermesWorkspaceBackend(service=object())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homes = {
                "default": root / "default",
                "research": root / "research",
            }
            project_ids = {}
            for agent_id, home in homes.items():
                (home / "workspace").mkdir(parents=True)
                with projects_db.connect_closing(home / "projects.db") as connection:
                    project_ids[agent_id] = projects_db.create_project(
                        connection,
                        name=f"{agent_id.title()} Workspace",
                        folders=[str(home / "workspace")],
                    )

            with (
                patch("hermes_cli.profiles.profile_exists", return_value=True),
                patch(
                    "hermes_cli.profiles.get_profile_dir",
                    side_effect=lambda agent_id: homes[agent_id],
                ),
            ):
                default = asyncio.run(backend.projects_list({"agentId": "default"}))
                research = asyncio.run(backend.projects_list({"agentId": "research"}))
                asyncio.run(backend.projects_set_active({
                    "agentId": "research",
                    "workspaceId": project_ids["research"],
                }))

            self.assertEqual(
                [row["name"] for row in default["workspaces"]],
                ["Default Workspace"],
            )
            self.assertEqual(
                [row["name"] for row in research["workspaces"]],
                ["Research Workspace"],
            )
            with projects_db.connect_closing(
                homes["default"] / "projects.db"
            ) as connection:
                self.assertIsNone(projects_db.get_active_id(connection))
            with projects_db.connect_closing(
                homes["research"] / "projects.db"
            ) as connection:
                self.assertEqual(
                    projects_db.get_active_id(connection),
                    project_ids["research"],
                )

    def test_profile_records_use_the_lightweight_official_catalog(self) -> None:
        backend = HermesWorkspaceBackend(service=object())
        metadata = {
            "default": {
                "display_name": "Gordie",
                "description": "Primary household agent",
            },
            "research": {
                "display_name": "Research",
                "description": "Research specialist",
            },
        }

        with (
            patch(
                "hermes_cli.profiles.list_profile_names",
                return_value=["default", "research"],
            ),
            patch(
                "hermes_cli.profiles.get_profile_dir",
                side_effect=lambda name: Path("/profiles") / name,
            ),
            patch("hermes_cli.profiles.profile_exists", return_value=True),
            patch(
                "hermes_cli.profiles.read_profile_meta",
                side_effect=lambda path: metadata[path.name],
            ),
            patch(
                "hermes_cli.profiles.list_profiles",
                side_effect=AssertionError("skill-counting catalog must not be used"),
            ),
        ):
            records = asyncio.run(backend._profile_records())

        self.assertEqual(
            records,
            [
                {
                    "id": "default",
                    "display_name": "Gordie",
                    "ui_display_name": "",
                    "description": "Primary household agent",
                    "is_default": True,
                    "has_avatar": False,
                },
                {
                    "id": "research",
                    "display_name": "Research",
                    "ui_display_name": "",
                    "description": "Research specialist",
                    "is_default": False,
                    "has_avatar": False,
                },
            ],
        )

    def test_agent_list_projects_only_identity_description_and_soul(self) -> None:
        backend = _ProfileBackend()

        result = asyncio.run(backend.agents_list({}))

        self.assertEqual([agent["id"] for agent in result["agents"]], ["default", "research"])
        self.assertEqual(result["agents"][0]["name"], "Gordie")
        self.assertEqual(result["agents"][1]["name"], "Research")
        self.assertEqual(result["agents"][0]["instructions"], "Be useful and concise.")
        self.assertNotIn("path", repr(result).lower())

    def test_agent_list_projects_avatar_presence_without_loading_the_asset(self) -> None:
        class _AvatarBackend(_ProfileBackend):
            async def _profile_records(self):
                return [
                    {
                        "id": "default",
                        "display_name": "Gordie",
                        "description": "Primary household agent",
                        "is_default": True,
                        "has_avatar": True,
                    }
                ]

            async def _profile_avatar(self, agent_id):
                raise AssertionError("agents.list must not load avatar bytes")

        backend = _AvatarBackend()

        try:
            result = asyncio.run(backend.agents_list({}))
        except AssertionError as exc:
            self.fail(str(exc))

        self.assertIs(result["agents"][0]["hasAvatar"], True)
        self.assertNotIn("avatar", result["agents"][0])
        self.assertNotIn("path", repr(result).lower())

    def test_agent_list_omits_oversized_legacy_avatar_without_reading_blob(self) -> None:
        class _OversizedAvatarBackend(_ProfileBackend):
            async def _profile_records(self):
                return [
                    {
                        "id": "default",
                        "display_name": "Gordie",
                        "description": "Primary household agent",
                        "is_default": True,
                        "has_avatar": True,
                    }
                ]

        hermes_cli = ModuleType("hermes_cli")
        hermes_cli.__path__ = []  # type: ignore[attr-defined]
        profiles = ModuleType("hermes_cli.profiles")
        with tempfile.TemporaryDirectory() as directory:
            profile_dir = Path(directory) / "default"
            assets_dir = profile_dir / "assets"
            assets_dir.mkdir(parents=True)
            (assets_dir / "avatar.png").write_bytes(b"x" * 2_000_001)
            profiles.profile_exists = lambda profile: profile == "default"
            profiles.get_profile_dir = lambda profile: profile_dir

            with (
                patch.dict(sys.modules, {
                    "hermes_cli": hermes_cli,
                    "hermes_cli.profiles": profiles,
                }),
                patch.object(
                    Path,
                    "read_bytes",
                    side_effect=AssertionError("oversized avatar must not be read"),
                ),
            ):
                try:
                    result = asyncio.run(_OversizedAvatarBackend().agents_list({}))
                except AssertionError as exc:
                    self.fail(str(exc))
                except WorkspaceControlError as exc:
                    self.fail(
                        "agents.list should omit oversized legacy avatars "
                        f"instead of failing: {exc}"
                    )

        self.assertEqual(result["agents"][0]["id"], "default")
        self.assertNotIn("avatar", result["agents"][0])

    def test_agent_avatar_get_uses_the_native_hermes_profile_asset_method(self) -> None:
        calls = []

        def dispatch(request):
            calls.append(request)
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "found": True,
                    "mime": "image/png",
                    "size": 8,
                    "data": "data:image/png;base64,iVBORw0KGgo=",
                },
            }

        tui_gateway = ModuleType("tui_gateway")
        tui_gateway.__path__ = []  # type: ignore[attr-defined]
        server = ModuleType("tui_gateway.server")
        server.handle_request = dispatch
        backend = HermesWorkspaceBackend(service=object())

        operation = getattr(backend, "agents_avatar_get", None)
        self.assertTrue(callable(operation), "agents.avatar.get is unavailable")
        with patch.dict(sys.modules, {
            "tui_gateway": tui_gateway,
            "tui_gateway.server": server,
        }):
            result = asyncio.run(operation({"agentId": "default"}))

        self.assertEqual(
            calls,
            [{
                "jsonrpc": "2.0",
                "id": "loopdy-profile-asset",
                "method": "profiles.get_asset",
                "params": {"name": "default", "asset": "avatar"},
            }],
        )
        self.assertEqual(
            result,
            {
                "agentId": "default",
                "avatar": {
                    "mimeType": "image/png",
                    "byteCount": 8,
                    "sha256": "TEtqO-ExSrhhOL70MU3eAi5gCWDYaJosj4YxgC0g2rY",
                    "data": "data:image/png;base64,iVBORw0KGgo=",
                },
            },
        )

    def test_agent_avatar_get_returns_null_when_the_native_asset_is_missing(self) -> None:
        def dispatch(request):
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"found": False},
            }

        tui_gateway = ModuleType("tui_gateway")
        tui_gateway.__path__ = []  # type: ignore[attr-defined]
        server = ModuleType("tui_gateway.server")
        server.handle_request = dispatch
        backend = HermesWorkspaceBackend(service=object())

        operation = getattr(backend, "agents_avatar_get", None)
        self.assertTrue(callable(operation), "agents.avatar.get is unavailable")
        with patch.dict(sys.modules, {
            "tui_gateway": tui_gateway,
            "tui_gateway.server": server,
        }):
            result = asyncio.run(operation({"agentId": "research"}))

        self.assertEqual(result, {"agentId": "research", "avatar": None})

    def test_agent_avatar_set_uses_the_native_method_without_echoing_image_data(self) -> None:
        calls = []
        avatar = {
            "mimeType": "image/png",
            "byteCount": 8,
            "sha256": "TEtqO-ExSrhhOL70MU3eAi5gCWDYaJosj4YxgC0g2rY",
            "data": "data:image/png;base64,iVBORw0KGgo=",
        }

        def dispatch(request):
            calls.append(request)
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"ok": True, "asset": "avatar", "size": 8},
            }

        tui_gateway = ModuleType("tui_gateway")
        tui_gateway.__path__ = []  # type: ignore[attr-defined]
        server = ModuleType("tui_gateway.server")
        server.handle_request = dispatch
        backend = HermesWorkspaceBackend(service=object())

        operation = getattr(backend, "agents_avatar_set", None)
        self.assertTrue(callable(operation), "agents.avatar.set is unavailable")
        with patch.dict(sys.modules, {
            "tui_gateway": tui_gateway,
            "tui_gateway.server": server,
        }):
            result = asyncio.run(operation({
                "agentId": "default",
                "avatar": avatar,
            }))

        self.assertEqual(
            calls[0]["params"],
            {
                "name": "default",
                "asset": "avatar",
                "data": avatar["data"],
            },
        )
        self.assertEqual(result, {"agentId": "default", "hasAvatar": True})
        self.assertNotIn("data", repr(result))

    def test_agent_avatar_set_deletes_through_the_native_method(self) -> None:
        calls = []

        def dispatch(request):
            calls.append(request)
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"ok": True, "asset": "avatar", "size": 0, "removed": 1},
            }

        tui_gateway = ModuleType("tui_gateway")
        tui_gateway.__path__ = []  # type: ignore[attr-defined]
        server = ModuleType("tui_gateway.server")
        server.handle_request = dispatch
        backend = HermesWorkspaceBackend(service=object())

        operation = getattr(backend, "agents_avatar_set", None)
        self.assertTrue(callable(operation), "agents.avatar.set is unavailable")
        with patch.dict(sys.modules, {
            "tui_gateway": tui_gateway,
            "tui_gateway.server": server,
        }):
            result = asyncio.run(operation({
                "agentId": "default",
                "avatar": None,
            }))

        self.assertEqual(
            calls[0]["params"],
            {"name": "default", "asset": "avatar", "clear": True},
        )
        self.assertEqual(result, {"agentId": "default", "hasAvatar": False})

    def test_agent_update_persists_avatar_through_official_profile_asset_surface(self) -> None:
        backend = _ProfileBackend()
        backend.avatar_is_present = True
        avatar = {
            "mimeType": "image/png",
            "byteCount": 8,
            "sha256": "sha256-agent-avatar-0001",
            "data": "data:image/png;base64,iVBORw0KGgo=",
        }

        result = asyncio.run(backend.agents_update({
            "agentId": "default",
            "agent": {
                "name": "Gordie",
                "role": "Primary household agent",
                "summary": "Primary household agent",
                "instructions": "Be useful and concise.",
                "isDefault": True,
                "avatar": avatar,
            },
        }))

        self.assertEqual(backend.saved_avatar, ("default", avatar))
        self.assertEqual(result["agent"]["avatar"], avatar)
        self.assertIs(result["agent"]["hasAvatar"], True)

    def test_agent_create_reports_canonical_hermes_avatar_presence(self) -> None:
        class _CreateBackend(_ProfileBackend):
            async def _create_profile(
                self,
                *,
                agent_id,
                display_name,
                description,
                instructions,
            ):
                self.created_profile = {
                    "agent_id": agent_id,
                    "display_name": display_name,
                    "description": description,
                    "instructions": instructions,
                }

        backend = _CreateBackend()
        backend.avatar_is_present = True

        result = asyncio.run(backend.agents_create({
            "agent": {
                "name": "Weather Guide",
                "role": "Forecast specialist",
                "summary": "Tracks local conditions.",
                "instructions": "Use the weather tool.",
                "isDefault": False,
            },
        }))

        self.assertEqual(backend.created_profile["agent_id"], "weather-guide")
        self.assertIs(result["agent"]["hasAvatar"], True)

    def test_agent_update_reports_current_presence_instead_of_echoing_avatar_intent(self) -> None:
        backend = _ProfileBackend()
        backend.avatar_is_present = False
        avatar = {
            "mimeType": "image/png",
            "byteCount": 8,
            "sha256": "sha256-agent-avatar-0001",
            "data": "data:image/png;base64,iVBORw0KGgo=",
        }

        result = asyncio.run(backend.agents_update({
            "agentId": "default",
            "agent": {
                "name": "Gordie",
                "role": "Primary household agent",
                "summary": "Primary household agent",
                "instructions": "Be useful and concise.",
                "isDefault": True,
                "avatar": avatar,
            },
        }))

        self.assertIs(result["agent"]["hasAvatar"], False)

    def test_agent_update_preserves_soul_without_explicit_confirmed_change(self) -> None:
        backend = _ProfileBackend()

        result = asyncio.run(backend.agents_update({
            "agentId": "default",
            "agent": {
                "name": "Gordie",
                "role": "Household chief of staff",
                "summary": "Keeps the household moving.",
                # A stale or fallback form value must never authorize a SOUL write.
                "instructions": "Be useful and concise.",
                "isDefault": True,
            },
        }))

        self.assertIsNone(backend.updated_profile["instructions"])
        self.assertEqual(
            result["agent"]["instructions"],
            "Be useful and concise.",
        )

    def test_agent_update_writes_soul_only_with_confirmed_matching_digest(self) -> None:
        backend = _ProfileBackend()
        original = "Be useful and concise."
        expected_digest = base64.urlsafe_b64encode(
            hashlib.sha256(original.encode("utf-8")).digest()
        ).decode("ascii").rstrip("=")

        result = asyncio.run(backend.agents_update({
            "agentId": "default",
            "agent": {
                "name": "Gordie",
                "role": "Household chief of staff",
                "summary": "Keeps the household moving.",
                "instructions": "A stale transport copy that is not authoritative.",
                "isDefault": True,
            },
            "soulUpdate": {
                "confirmed": True,
                "expectedSha256": expected_digest,
                "instructions": "Deliberately revised instructions.",
            },
        }))

        self.assertEqual(
            backend.updated_profile["instructions"],
            "Deliberately revised instructions.",
        )
        self.assertEqual(
            result["agent"]["instructions"],
            "Deliberately revised instructions.",
        )

    def test_agent_update_rejects_stale_soul_confirmation_without_writing(self) -> None:
        backend = _ProfileBackend()

        with self.assertRaises(WorkspaceConflictError):
            asyncio.run(backend.agents_update({
                "agentId": "default",
                "agent": {
                    "name": "Gordie",
                    "role": "Household chief of staff",
                    "summary": "Keeps the household moving.",
                    "instructions": "Ignored transport copy.",
                    "isDefault": True,
                },
                "soulUpdate": {
                    "confirmed": True,
                    "expectedSha256": "A" * 43,
                    "instructions": "Must not be written.",
                },
            }))

        self.assertFalse(hasattr(backend, "updated_profile"))

    def test_agent_list_bounds_role_without_discarding_full_summary(self) -> None:
        class _LongDescriptionBackend(_ProfileBackend):
            async def _profile_records(self):
                return [
                    {
                        "id": "default",
                        "display_name": "Gordie",
                        "description": "A" * 335,
                        "is_default": True,
                    }
                ]

        result = asyncio.run(_LongDescriptionBackend().agents_list({}))

        self.assertEqual(len(result["agents"][0]["role"].encode("utf-8")), 160)
        self.assertEqual(result["agents"][0]["summary"], "A" * 335)

    def test_agent_defaults_get_keeps_each_scope_distinct_and_strips_provider_credentials(self) -> None:
        backend = _ProfileBackend()

        result = asyncio.run(backend.agent_defaults_get({"agentId": "default"}))

        self.assertEqual(result["defaults"]["mainChats"], {
            "providerId": "nous",
            "modelId": "Hermes-4-405B",
            "reasoningEffort": "high",
        })
        self.assertEqual(result["defaults"]["subagents"]["modelId"], "gpt-5.6")
        self.assertEqual(result["defaults"]["scheduledTasks"], {
            "providerId": "anthropic",
            "modelId": "claude-opus-4.1",
            "reasoningEffort": "low",
        })
        self.assertEqual(result["providers"][0]["id"], "nous")
        self.assertNotIn("must-never-cross-link", repr(result))

    def test_agent_defaults_get_accepts_hermes_normalized_model_and_named_moa_presets(self) -> None:
        backend = _NormalizedHermesProfileBackend()

        result = asyncio.run(backend.agent_defaults_get({"agentId": "default"}))

        self.assertEqual(result["defaults"]["mainChats"], {
            "providerId": "openai-codex",
            "modelId": "gpt-5.6-sol",
            "reasoningEffort": "high",
        })
        self.assertEqual(result["providers"][0]["models"], [
            "Frontier Tuned",
            "Small Stuff",
        ])

    def test_agent_defaults_get_skips_current_hermes_unconfigured_provider_rows(self) -> None:
        class _CurrentCatalogBackend(_ProfileBackend):
            async def _model_options(self, agent_id):
                options = await super()._model_options(agent_id)
                options["providers"].insert(1, {
                    "slug": "anthropic",
                    "name": "Anthropic",
                    "models": [],
                    "configured": False,
                })
                return options

        result = asyncio.run(
            _CurrentCatalogBackend().agent_defaults_get({"agentId": "default"})
        )

        self.assertEqual(
            [provider["id"] for provider in result["providers"]],
            ["nous", "openai"],
        )

    def test_agent_defaults_get_uses_native_hermes_config_and_model_option_rpcs(self) -> None:
        requests: list[dict] = []

        def handle_request(request):
            requests.append(request)
            method = request["method"]
            if method == "config.get":
                result = {
                    "config": {
                        "model": {
                            "provider": "nous",
                            "default": "Hermes-4-405B",
                        },
                        "agent": {"reasoning_effort": "high"},
                        "delegation": {
                            "provider": "openai",
                            "model": "gpt-5.6",
                            "reasoning_effort": "medium",
                        },
                        "cron": {
                            "model_provider": "anthropic",
                            "model": "claude-opus-4.1",
                        },
                    }
                }
            elif method == "model.options":
                result = {
                    "provider": "nous",
                    "providers": [{
                        "slug": "nous",
                        "name": "Nous Research",
                        "models": ["Hermes-4-405B"],
                    }],
                }
            else:
                raise AssertionError(f"Unexpected Hermes method: {method}")
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": result,
            }

        server = ModuleType("tui_gateway.server")
        server.handle_request = handle_request
        package = ModuleType("tui_gateway")
        package.__path__ = []
        with patch.dict(
            sys.modules,
            {"tui_gateway": package, "tui_gateway.server": server},
        ):
            result = asyncio.run(
                HermesWorkspaceBackend(service=object()).agent_defaults_get(
                    {"agentId": "default"}
                )
            )

        self.assertEqual(len(requests), 2)
        params_by_method = {
            request["method"]: request["params"]
            for request in requests
        }
        self.assertEqual(
            params_by_method,
            {
                "config.get": {"profile": "default", "key": "full"},
                "model.options": {
                    "profile": "default",
                    "explicit_only": True,
                },
            },
        )
        self.assertEqual(result["defaults"]["mainChats"]["modelId"], "Hermes-4-405B")
        self.assertEqual(result["providers"][0]["id"], "nous")

    def test_agent_defaults_set_writes_three_independent_hermes_blocks(self) -> None:
        backend = _ProfileBackend()
        defaults = {
            "mainChats": {
                "providerId": "openai",
                "modelId": "gpt-5.6",
                "reasoningEffort": "high",
            },
            "subagents": {
                "providerId": "anthropic",
                "modelId": "claude-sonnet-4.1",
                "reasoningEffort": "medium",
            },
            "scheduledTasks": {
                "providerId": "nous",
                "modelId": "Hermes-4-70B",
                "reasoningEffort": "low",
            },
        }

        result = asyncio.run(backend.agent_defaults_set({
            "agentId": "default",
            "defaults": defaults,
        }))

        agent_id, config = backend.saved_config
        self.assertEqual(agent_id, "default")
        self.assertEqual(config["model"], {"provider": "openai", "default": "gpt-5.6"})
        self.assertEqual(config["agent"]["reasoning_effort"], "high")
        self.assertEqual(config["delegation"], {
            "provider": "anthropic",
            "model": "claude-sonnet-4.1",
            "reasoning_effort": "medium",
        })
        self.assertEqual(config["cron"], {
            "model_provider": "nous",
            "model": "Hermes-4-70B",
        })
        self.assertEqual(
            config["platforms"]["loopdy"]["extra"]["agent_defaults"]
                ["scheduled_tasks"]["reasoning_effort"],
            "low",
        )
        self.assertEqual(result["defaults"], defaults)

    def test_sessions_list_maps_cwd_to_deepest_profile_project_without_leaking_paths(self) -> None:
        class ProjectSessionBackend(_ProfileBackend):
            async def _session_catalog(self, agent_id):
                return {
                    "sessions": [
                        {
                            "id": "default-match",
                            "profile": "default",
                            "source": "loopdy",
                            "chat_id": "default-match-chat",
                            "title": "Default project",
                            "preview": "Matched",
                            "message_count": 1,
                            "started_at": 1_788_000_000,
                            "last_active": 1_788_000_100,
                            "cwd": "/Users/private/home/../home",
                        },
                        {
                            "id": "default-child",
                            "profile": "default",
                            "source": "loopdy",
                            "chat_id": "default-child-chat",
                            "title": "Child directory",
                            "preview": "Matched through parent folder",
                            "message_count": 1,
                            "started_at": 1_788_000_000,
                            "last_active": 1_788_000_090,
                            "cwd": "/Users/private/home/child",
                        },
                        {
                            "id": "research-match",
                            "profile": "research",
                            "source": "local",
                            "chat_id": None,
                            "title": "Research project",
                            "preview": "Matched",
                            "message_count": 1,
                            "started_at": 1_788_000_000,
                            "last_active": 1_788_000_080,
                            "cwd": "/Users/private/research",
                        },
                    ]
                }

            async def _projects_catalog(self, agent_id):
                self.project_catalog_agent_ids = getattr(
                    self, "project_catalog_agent_ids", []
                ) + [agent_id]
                if agent_id == "research":
                    return {"projects": [{
                        "id": "project-research",
                        "name": "Research",
                        "archived": False,
                        "primary_path": "/Users/private/research",
                        "folders": [],
                    }]}
                return {
                    "active_id": "project-home",
                    "projects": [
                        {
                            "id": "project-home",
                            "name": "Home",
                            "archived": False,
                            "primary_path": "/Users/private/home",
                            "folders": [],
                        },
                        {
                            "id": "project-home-child",
                            "name": "Home Child",
                            "archived": False,
                            "primary_path": "/Users/private/home/child",
                            "folders": [],
                        },
                    ],
                }

        backend = ProjectSessionBackend()
        result = asyncio.run(backend.sessions_list({}))

        self.assertEqual(
            [(row["workspaceId"], row["workspaceName"]) for row in result["sessions"]],
            [
                ("project-home", "Home"),
                ("project-home-child", "Home Child"),
                ("project-research", "Research"),
            ],
        )
        self.assertEqual(backend.project_catalog_agent_ids, ["default", "research"])
        projected = json.dumps(result)
        self.assertNotIn("/Users/private", projected)
        self.assertNotIn("cwd", projected)

    def test_sessions_list_fails_closed_for_ambiguous_or_archived_project_paths(self) -> None:
        class AmbiguousProjectBackend(_ProfileBackend):
            async def _session_catalog(self, agent_id):
                value = await super()._session_catalog(agent_id)
                value["sessions"][0]["cwd"] = "/Users/private/home"
                return value

            async def _projects_catalog(self, agent_id):
                return {"projects": [
                    {
                        "id": "project-home-a",
                        "name": "Home A",
                        "archived": False,
                        "primary_path": "/Users/private/home",
                        "folders": [],
                    },
                    {
                        "id": "project-home-b",
                        "name": "Home B",
                        "archived": False,
                        "primary_path": "/Users/private/home",
                        "folders": [],
                    },
                    {
                        "id": "project-archived",
                        "name": "Archived",
                        "archived": True,
                        "primary_path": "/Users/private/archive",
                        "folders": [],
                    },
                ]}

        result = asyncio.run(AmbiguousProjectBackend().sessions_list({"agentId": "default"}))

        self.assertIsNone(result["sessions"][0]["workspaceId"])
        self.assertIsNone(result["sessions"][0]["workspaceName"])
        self.assertNotIn("/Users/private", json.dumps(result))

    def test_sessions_list_projects_stable_visible_and_stored_coordinates(self) -> None:
        backend = _ProfileBackend()

        result = asyncio.run(backend.sessions_list({"agentId": "default"}))

        self.assertEqual(backend.session_agent_id, "default")
        self.assertEqual(result["sessions"], [
            {
                "storedId": "stored-session-0001",
                "profile": "default",
                "source": "loopdy",
                "chatId": "visible-session-0001",
                "visibleId": "visible-session-0001",
                "title": "Weather follow-up",
                "preview": "Check tomorrow too.",
                "messageCount": 4,
                "startedAt": 1_788_000_000,
                "lastActive": 1_788_000_100,
                "isActive": False,
                "isPinned": True,
                "workspaceId": None,
                "workspaceName": None,
            }
        ])
        self.assertNotIn("system_prompt", repr(result))

    def test_sessions_update_and_delete_use_profile_scoped_durable_coordinates(self) -> None:
        backend = _ProfileBackend()

        updated = asyncio.run(backend.sessions_update({
            "storedId": "stored-session-0001",
            "agentId": "default",
            "title": "Renamed session",
            "pinned": True,
            "archived": False,
        }))
        deleted = asyncio.run(backend.sessions_delete({
            "storedId": "stored-session-0001",
            "agentId": "default",
        }))

        self.assertEqual(updated, {
            "storedId": "stored-session-0001",
            "agentId": "default",
            "updated": True,
        })
        self.assertEqual(deleted, {
            "storedId": "stored-session-0001",
            "agentId": "default",
            "deleted": True,
        })
        self.assertEqual(backend.session_updates, [(
            "stored-session-0001",
            {
                "profile": "default",
                "title": "Renamed session",
                "pinned": True,
                "archived": False,
            },
        )])
        self.assertEqual(backend.session_deletes, [
            ("stored-session-0001", "default"),
        ])

    def test_sessions_update_rejects_blank_or_oversized_titles(self) -> None:
        backend = _ProfileBackend()

        for title in ("   ", "x" * 101):
            with self.assertRaises(WorkspaceControlError):
                asyncio.run(backend.sessions_update({
                    "storedId": "stored-session-0001",
                    "agentId": "default",
                    "title": title,
                }))

        self.assertEqual(backend.session_updates, [])

    def test_sessions_list_reconciles_stale_persisted_activity_with_live_owner(self) -> None:
        observed = []

        class _StaleActiveBackend(_ProfileBackend):
            def __init__(self):
                super().__init__()
                self.session_active_getter = self._active

            def _active(self, profile, visible_id, stored_id):
                observed.append((profile, visible_id, stored_id))
                return False

            async def _session_catalog(self, agent_id):
                value = await super()._session_catalog(agent_id)
                value["sessions"][0]["is_active"] = True
                return value

        result = asyncio.run(_StaleActiveBackend().sessions_list({"agentId": "default"}))

        self.assertFalse(result["sessions"][0]["isActive"])
        self.assertEqual(observed, [(
            "default",
            "visible-session-0001",
            "stored-session-0001",
        )])

    def test_sessions_list_keeps_every_reset_row_without_merging_chat_transcripts(self) -> None:
        class _ResetLineageBackend(_ProfileBackend):
            async def _session_catalog(self, agent_id):
                self.session_agent_id = agent_id
                return {
                    "sessions": [
                        {
                            "id": "new-active-reset-row",
                            "profile": "default",
                            "source": "loopdy",
                            "chat_id": "link-stable-chat",
                            "parent_session_id": "older-transcript-row",
                            "title": None,
                            "preview": "",
                            "message_count": 0,
                            "started_at": 1_788_000_200,
                            "last_active": 1_788_000_200,
                            "is_active": True,
                        },
                        {
                            "id": "older-transcript-row",
                            "profile": "default",
                            "source": "loopdy",
                            "chat_id": "link-stable-chat",
                            "title": "Earlier conversation",
                            "preview": "An exact earlier turn.",
                            "message_count": 12,
                            "started_at": 1_788_000_000,
                            "last_active": 1_788_000_100,
                            "is_active": False,
                        },
                    ]
                }

        result = asyncio.run(
            _ResetLineageBackend().sessions_list({"agentId": "default"})
        )

        self.assertEqual(
            [row["storedId"] for row in result["sessions"]],
            ["new-active-reset-row", "older-transcript-row"],
        )
        self.assertEqual(
            [row["visibleId"] for row in result["sessions"]],
            ["link-stable-chat", "older-transcript-row"],
        )
        self.assertEqual(
            [row["isActive"] for row in result["sessions"]],
            [True, False],
        )
        self.assertEqual(
            [row["messageCount"] for row in result["sessions"]],
            [0, 12],
        )

    def test_sessions_list_orders_authoritative_rows_newest_first(self) -> None:
        class _OutOfOrderBackend(_ProfileBackend):
            async def _session_catalog(self, agent_id):
                return {
                    "sessions": [
                        {
                            "id": "older-row",
                            "profile": "default",
                            "source": "loopdy",
                            "chat_id": "older-chat",
                            "title": "Older",
                            "preview": "Older turn",
                            "message_count": 2,
                            "started_at": 1_788_000_000,
                            "last_active": 1_788_000_100,
                        },
                        {
                            "id": "newer-row",
                            "profile": "default",
                            "source": "loopdy",
                            "chat_id": "newer-chat",
                            "title": "Newer",
                            "preview": "Newer turn",
                            "message_count": 2,
                            "started_at": 1_788_000_050,
                            "last_active": 1_788_000_200,
                        },
                    ]
                }

        result = asyncio.run(_OutOfOrderBackend().sessions_list({}))

        self.assertEqual(
            [row["visibleId"] for row in result["sessions"]],
            ["newer-chat", "older-chat"],
        )

    def test_session_history_includes_only_safe_exact_session_runtime(self) -> None:
        class RuntimeBackend(_ProfileBackend):
            async def _session_detail(self, session_id, agent_id):
                return {"id": session_id, "profile": agent_id, "model": "saved-model",
                        "model_config": json.dumps({"gateway_runtime": {
                            "provider": "openai", "base_url": "https://private.invalid"},
                            "api_key": "never-export-this"})}
        result = asyncio.run(RuntimeBackend().sessions_history({
            "storedId": "stored-session-0001", "agentId": "default"}))
        self.assertEqual(result.get("runtime"), {"model": "saved-model", "provider": "openai"})
        self.assertNotIn("private.invalid", json.dumps(result))
        self.assertNotIn("never-export-this", json.dumps(result))

    def test_session_runtime_omits_mismatched_or_malformed_metadata(self) -> None:
        for metadata in (
            {"id": "another-session", "profile": "default", "model": "wrong"},
            {"id": "stored-session-0001", "profile": "other-agent", "model": "wrong"},
            {"id": "stored-session-0001", "profile": "default", "model": "x" * 161},
        ):
            class RuntimeBackend(_ProfileBackend):
                async def _session_detail(self, session_id, agent_id):
                    return metadata
            result = asyncio.run(RuntimeBackend().sessions_history({
                "storedId": "stored-session-0001", "agentId": "default"}))
            self.assertNotIn("runtime", result)
            self.assertEqual(len(result["messages"]), 3)

    def test_session_runtime_prefers_current_override_and_omits_secrets(self) -> None:
        class RuntimeBackend(_ProfileBackend):
            async def _session_detail(self, session_id, agent_id):
                return {"id": session_id, "profile": agent_id, "model": "last-used"}
        backend = RuntimeBackend()
        async def current(agent_id, stored_id):
            self.assertEqual((agent_id, stored_id), ("default", "stored-session-0001"))
            return {"model": "selected-next", "provider": "anthropic", "base_url": "private", "api_key": "secret"}
        backend.session_runtime_getter = current
        result = asyncio.run(backend.sessions_history({"storedId": "stored-session-0001", "agentId": "default"}))
        self.assertEqual(result["runtime"], {"model": "selected-next", "provider": "anthropic"})

    def test_session_runtime_read_failure_does_not_block_history(self) -> None:
        class RuntimeBackend(_ProfileBackend):
            async def _session_detail(self, session_id, agent_id):
                raise RuntimeError("unavailable")
        result = asyncio.run(RuntimeBackend().sessions_history({"storedId": "stored-session-0001", "agentId": "default"}))
        self.assertNotIn("runtime", result)
        self.assertEqual(len(result["messages"]), 3)

    def test_session_history_preserves_renderable_rich_hermes_message_records(self) -> None:
        backend = _ProfileBackend()

        result = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
        }))

        self.assertEqual(backend.history_coordinate, ("stored-session-0001", "default"))
        self.assertEqual(
            [item["role"] for item in result["messages"]],
            ["user", "assistant", "tool"],
        )
        assistant = result["messages"][1]
        self.assertEqual(assistant["reasoning_content"], "Checked the forecast.")
        self.assertEqual(assistant["tool_calls"][0]["function"]["name"], "weather")
        self.assertEqual(assistant["display_metadata"]["subagent_id"], "forecast-agent")
        tool = result["messages"][2]
        self.assertEqual(tool["id"], "3")
        self.assertEqual(tool["row_id"], 3)
        self.assertEqual(tool["tool_call_id"], "weather-call-1")
        self.assertEqual(tool["tool_name"], "weather")
        self.assertEqual(tool["display_metadata"]["activity_id"], "activity-1")
        self.assertEqual(
            tool["display_metadata"]["bot_handoff"],
            {"from": "gordie", "to": "forecast-agent"},
        )
        self.assertNotIn("must not leak", repr(result["messages"]))
        self.assertNotIn("nextOffset", result)

    def test_session_history_pages_complete_recent_turns_on_demand(self) -> None:
        class _TurnPagedHistoryBackend(_ProfileBackend):
            def __init__(self) -> None:
                super().__init__()
                self.history_offsets: list[int] = []

            async def _session_messages(
                self,
                stored_id,
                agent_id,
                *,
                include_compacted=False,
                offset=0,
            ):
                self.history_offsets.append(offset)
                rows = [
                    {"id": 1, "role": "user", "content": "Question one"},
                    {"id": 2, "role": "assistant", "content": "Checking one", "reasoning_content": "Reason one"},
                    {"id": 3, "role": "tool", "content": "Tool one", "tool_call_id": "call-one", "tool_name": "lookup"},
                    {"id": 4, "role": "assistant", "content": "Answer one"},
                    {"id": 5, "role": "user", "content": "Question two"},
                    {"id": 6, "role": "assistant", "content": "Answer two"},
                    {"id": 7, "role": "user", "content": "Question three"},
                    {"id": 8, "role": "assistant", "content": "Checking three", "reasoning_content": "Reason three"},
                    {"id": 9, "role": "tool", "content": "Tool three", "tool_call_id": "call-three", "tool_name": "lookup"},
                    {"id": 10, "role": "assistant", "content": "Answer three"},
                ]
                return {"messages": rows[: max(0, len(rows) - offset)][-500:]}

        backend = _TurnPagedHistoryBackend()

        first = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
            "turnLimit": 2,
        }))
        second = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
            "offset": first["nextOffset"],
            "turnLimit": 2,
        }))

        self.assertEqual([row["id"] for row in first["messages"]], ["5", "6", "7", "8", "9", "10"])
        self.assertEqual(first["nextOffset"], 6)
        self.assertEqual([row["id"] for row in second["messages"]], ["1", "2", "3", "4"])
        self.assertNotIn("nextOffset", second)
        self.assertEqual(backend.history_offsets, [0, 6])
        self.assertEqual(first["messages"][3]["reasoning_content"], "Reason three")
        self.assertEqual(first["messages"][4]["tool_call_id"], "call-three")

    def test_session_history_pages_backward_with_a_byte_bounded_optional_offset(self) -> None:
        backend = _PagedHistoryBackend()

        first = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
            "offset": 0,
        }))
        second = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
            "offset": first["nextOffset"],
        }))
        third = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
            "offset": second["nextOffset"],
        }))

        self.assertEqual(backend.history_offsets, [0, 1, 2])
        self.assertEqual([[row["id"] for row in page["messages"]] for page in (
            first,
            second,
            third,
        )], [["3"], ["2"], ["1"]])
        self.assertEqual(first["nextOffset"], 1)
        self.assertEqual(second["nextOffset"], 2)
        self.assertNotIn("nextOffset", third)
        for page in (first, second, third):
            encoded = json.dumps(
                page,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            self.assertLessEqual(len(encoded), 160_000)

    def test_session_history_resolves_loopdy_visible_id_to_hermes_stored_id(self) -> None:
        backend = _VisibleIdHistoryBackend()

        result = asyncio.run(backend.sessions_history({
            "storedId": "visible-session-0001",
            "agentId": "default",
        }))

        self.assertEqual(backend.history_coordinate, (
            "stored-session-0001",
            "default",
        ))
        self.assertEqual(result["storedId"], "stored-session-0001")
        self.assertEqual([item["role"] for item in result["messages"]], [
            "user",
            "assistant",
            "tool",
        ])

    def test_session_history_includes_hermes_compacted_display_rows(self) -> None:
        backend = _CompactedHistoryBackend()

        result = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
        }))

        self.assertTrue(backend.history_include_compacted)
        self.assertEqual(
            [item["content"] for item in result["messages"]],
            ["Earlier question.", "Earlier answer.", "Compaction summary."],
        )

    def test_session_history_falls_back_when_display_content_is_empty(self) -> None:
        backend = _EmptyDisplayContentHistoryBackend()

        result = asyncio.run(backend.sessions_history({
            "storedId": "stored-session-0001",
            "agentId": "default",
        }))

        self.assertEqual(
            [item["content"] for item in result["messages"]],
            ["What is the weather?", "It is sunny."],
        )

    def test_scheduled_task_create_applies_the_agent_cron_defaults_on_the_host(self) -> None:
        backend = _ProfileBackend()

        result = asyncio.run(backend.scheduled_tasks_create({
            "agentId": "default",
            "name": "Morning weather",
            "instructions": "Summarize the weather.",
            "schedule": "0 8 * * * America/Chicago",
            "delivery": "loopdy",
        }))

        agent_id, create = backend.cron_created
        self.assertEqual(agent_id, "default")
        self.assertEqual(create, {
            "name": "Morning weather",
            "prompt": "Summarize the weather.",
            "schedule": "0 8 * * * America/Chicago",
            "deliver": "loopdy",
            "provider": "anthropic",
            "model": "claude-opus-4.1",
        })
        self.assertEqual(backend.cron_updated, (
            "cron-job-0001", "default", {"reasoning_effort": "low"}
        ))
        self.assertEqual(result["task"]["id"], "cron-job-0001")
        self.assertNotIn("private.invalid", repr(result))
        self.assertNotIn("task.py", repr(result))

    def test_scheduled_task_list_projects_script_only_jobs_without_exposing_paths(self) -> None:
        class _ScriptOnlyBackend(_ProfileBackend):
            async def _cron_list(self, agent_id):
                row = self._job()
                row.update({
                    "prompt": "",
                    "script": "/private/automation.py",
                    "no_agent": True,
                })
                return [row]

        result = asyncio.run(_ScriptOnlyBackend().scheduled_tasks_list({
            "agentId": "default",
        }))

        self.assertEqual(
            result["tasks"][0]["instructions"],
            "Runs the configured automation.",
        )
        self.assertNotIn("automation.py", repr(result))

    def test_scheduled_task_delivery_targets_and_manual_channel_use_official_cron_fields(self) -> None:
        backend = _ProfileBackend()

        targets = asyncio.run(backend.scheduled_tasks_delivery_targets({}))
        created = asyncio.run(backend.scheduled_tasks_create({
            "agentId": "default",
            "name": "Morning weather",
            "instructions": "Summarize the weather.",
            "schedule": "0 8 * * 1,3,5",
            "delivery": "loopdy:device-fixture-01",
        }))
        updated = asyncio.run(backend.scheduled_tasks_update({
            "taskId": "cron-job-0001",
            "agentId": "default",
            "changes": {
                "name": "Morning weather",
                "instructions": "Summarize the weather.",
                "schedule": "0 8 * * 1,3,5",
                "delivery": "local",
            },
        }))

        self.assertEqual(targets, {"targets": [
            {"id": "local", "name": "Local (save only)", "homeTargetSet": True},
            {"id": "loopdy", "name": "Loopdy", "homeTargetSet": True},
            {"id": "slack", "name": "Slack", "homeTargetSet": False},
            {
                "id": "bot-chat:research",
                "name": "Bot Chat (research)",
                "homeTargetSet": True,
            },
        ]})
        self.assertEqual(backend.cron_created[1]["deliver"], "loopdy:device-fixture-01")
        self.assertEqual(created["task"]["delivery"], "loopdy:device-fixture-01")
        self.assertEqual(backend.cron_updated, (
            "cron-job-0001", "default", {
                "name": "Morning weather",
                "prompt": "Summarize the weather.",
                "schedule": "0 8 * * 1,3,5",
                "deliver": "local",
            }
        ))
        self.assertEqual(updated["task"]["delivery"], "local")
        self.assertNotIn("MUST_NOT_CROSS_LINK", repr(targets))

        for invalid in (
            "unknown:channel",
            "loopdy:",
            "loopdy:channel,slack:other",
            "loopdy:channel\u0000escape",
        ):
            with self.assertRaises(WorkspaceControlError):
                asyncio.run(backend.scheduled_tasks_create({
                    "agentId": "default",
                    "name": "Invalid delivery",
                    "instructions": "Do not save this.",
                    "schedule": "0 8 * * *",
                    "delivery": invalid,
                }))

    def test_scheduled_task_actions_remain_agent_bound(self) -> None:
        backend = _ProfileBackend()

        paused = asyncio.run(backend.scheduled_tasks_pause({
            "taskId": "cron-job-0001",
            "agentId": "default",
        }))
        self.assertEqual(backend.cron_action, ("pause", "cron-job-0001", "default"))
        self.assertFalse(paused["task"]["enabled"])

        deleted = asyncio.run(backend.scheduled_tasks_delete({
            "taskId": "cron-job-0001",
            "agentId": "default",
        }))
        self.assertEqual(backend.cron_action, ("delete", "cron-job-0001", "default"))
        self.assertEqual(deleted, {"taskId": "cron-job-0001", "deleted": True})

    def test_dashboard_load_cleans_stale_items_and_projects_only_display_fields(self) -> None:
        class _Store:
            def __init__(self):
                self.cleaned = []

            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                self.cleaned.append(("gateway", dismissed_at))

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                self.cleaned.append(("approvals", now, dismissed_at))

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                self.cleaned.append(("attention", created_before, dismissed_at))

            def list_events(self, *, limit, offset):
                if offset:
                    return []
                return [
                    {
                        "event_id": "event-0001",
                        "type": "session.completed",
                        "profile": "default",
                        "session_id": "session-0001",
                        "approval_id": None,
                        "detail": {
                            "summary": "Forecast finished",
                            "agent_name": "Gordie",
                            "command": "cat /private/secret",
                        },
                        "created_at": 1_788_000_000,
                        "is_read": False,
                        "is_pinned": True,
                        "push": {"private": "must not cross"},
                    }
                ]

        store = _Store()
        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=store),
            clock=lambda: 1_788_003_600,
            clarify_timeout=lambda: 3_600,
        )

        result = asyncio.run(backend.dashboard_load({}))

        self.assertEqual(store.cleaned, [
            ("gateway", 1_788_003_600),
            ("approvals", 1_788_003_600, 1_788_003_600),
            ("attention", 1_788_000_000, 1_788_003_600),
        ])
        self.assertEqual(result["events"][0]["detail"], {
            "summary": "Forecast finished",
            "agent_name": "Gordie",
        })
        self.assertFalse(result["events"][0]["isRead"])
        self.assertTrue(result["events"][0]["isPinned"])
        self.assertNotIn("private", repr(result).lower())

    def test_dashboard_load_bounds_transport_payload_to_recent_events(self) -> None:
        class _Store:
            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                pass

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                pass

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                pass

            def list_events(self, *, limit, offset):
                events = [
                    {
                        "event_id": f"event-{index:04d}",
                        "type": "channel.message",
                        "profile": "default",
                        "session_id": f"session-{index:04d}",
                        "approval_id": None,
                        "detail": {"message": "A useful update " + "x" * 480},
                        "created_at": 1_788_000_000 - index,
                        "is_read": False,
                        "is_pinned": index == 0,
                    }
                    for index in range(600)
                ]
                return events[offset : offset + limit]

        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=_Store()),
            clock=lambda: 1_788_003_600,
            clarify_timeout=lambda: 3_600,
        )

        result = asyncio.run(backend.dashboard_load({}))

        self.assertLessEqual(
            len(json.dumps(result, separators=(",", ":")).encode("utf-8")),
            160_000,
        )
        self.assertLessEqual(
            len(result["events"]), 200
        )
        self.assertEqual(result["events"][0]["eventId"], "event-0000")
        self.assertEqual(
            result["events"][-1]["eventId"],
            f"event-{len(result['events']) - 1:04d}",
        )

    def test_dashboard_load_projects_a_validated_persisted_generative_ui_card(self) -> None:
        card = {
            "schema": "loopdy.generative_ui",
            "version": 1,
            "component": "summary",
            "title": "Morning briefing",
            "body": "Three priorities are ready.",
        }

        class _Store:
            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                pass

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                pass

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                pass

            def list_events(self, *, limit, offset):
                if offset:
                    return []
                return [{
                    "event_id": "event-card-0001",
                    "type": "channel.message",
                    "profile": "default",
                    "session_id": None,
                    "approval_id": None,
                    "detail": {
                        "message": "Morning briefing",
                        "agent_name": "Gordie",
                        "generative_ui": card,
                    },
                    "created_at": 1_788_000_000,
                    "is_read": False,
                    "is_pinned": False,
                }]

        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=_Store()),
            clock=lambda: 1_788_003_600,
            clarify_timeout=lambda: 3_600,
        )

        result = asyncio.run(backend.dashboard_load({}))

        self.assertEqual(result["events"][0]["detail"]["generative_ui"], card)

    def test_dashboard_load_v1_is_exact_and_v2_request_validation_is_exact(self) -> None:
        class _Store:
            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                pass

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                pass

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                pass

            def list_events(self, *, limit, offset):
                if offset:
                    return []
                return [{
                    "event_id": "event-v1-0001",
                    "type": "job.completed",
                    "profile": "default",
                    "session_id": "cron_job-123_20260815_120000",
                    "job_id": "job-123",
                    "task_id": "job-123",
                    "approval_id": None,
                    "detail": {"agent_name": "Gordie"},
                    "created_at": 1_788_000_000,
                    "is_read": False,
                    "is_pinned": False,
                }]

        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=_Store()),
            clock=lambda: 1_788_003_600,
            clarify_timeout=lambda: 3_600,
        )

        self.assertEqual(asyncio.run(backend.dashboard_load({})), {
            "events": [{
                "eventId": "event-v1-0001",
                "type": "job.completed",
                "profile": "default",
                "sessionId": "cron_job-123_20260815_120000",
                "approvalId": None,
                "detail": {"agent_name": "Gordie", "job_id": "job-123", "task_id": "job-123"},
                "createdAt": 1_788_000_000,
                "isRead": False,
                "isPinned": False,
            }],
        })

        for payload in (
            {"schemaVersion": 1},
            {"schemaVersion": True},
            {"schemaVersion": "2"},
            {"schemaVersion": 2, "extra": True},
            {"schema_version": 2},
        ):
            with self.subTest(payload=payload), self.assertRaises(WorkspaceControlError):
                asyncio.run(backend.dashboard_load(payload))

    def test_dashboard_load_v2_enriches_completion_events_from_hermes_sources(self) -> None:
        class _Store:
            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                pass

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                pass

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                pass

            def list_events(self, *, limit, offset):
                if offset:
                    return []
                return [
                    {
                        "event_id": "event-job-completed",
                        "type": "job.completed",
                        "profile": "default",
                        "session_id": "cron_job-completed_20260815_120000",
                        "job_id": "job-completed",
                        "task_id": "01234567-89ab-4cde-8fab-0123456789ab",
                        "approval_id": None,
                        "detail": {
                            "agent_name": "Gordie",
                            "prompt": "must never cross link",
                        },
                        "created_at": 1_788_000_000,
                        "is_read": False,
                        "is_pinned": True,
                    },
                    {
                        "event_id": "event-job-failed",
                        "type": "job.failed",
                        "profile": "research",
                        "session_id": "cron_job-failed_20260815_120100",
                        "job_id": "legacy-job-coordinate",
                        "task_id": "fedcba98-7654-4cba-8765-fedcba987654",
                        "approval_id": None,
                        "detail": {"agent_name": "Researcher"},
                        "created_at": 1_788_000_060,
                        "is_read": True,
                        "is_pinned": False,
                    },
                    {
                        "event_id": "event-job-compressed",
                        "type": "job.completed",
                        "profile": "default",
                        "session_id": "compression-tip-0001",
                        "job_id": None,
                        "task_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                        "approval_id": None,
                        "detail": {"agent_name": "Gordie"},
                        "created_at": 1_788_000_120,
                        "is_read": False,
                        "is_pinned": False,
                    },
                ]

        class _Backend(HermesWorkspaceBackend):
            def __init__(self):
                super().__init__(
                    service=SimpleNamespace(store=_Store()),
                    clock=lambda: 1_788_003_600,
                    clarify_timeout=lambda: 3_600,
                )
                self.cron_profiles = []
                self.history_coordinates = []
                self.session_detail_coordinates = []

            async def _cron_list(self, agent_id):
                self.cron_profiles.append(agent_id)
                if agent_id == "default":
                    return [
                        {
                            "id": "job-completed",
                            "profile": agent_id,
                            "name": "Morning weather",
                            "prompt": "private scheduled instructions",
                        },
                        {
                            "id": "job-compressed",
                            "profile": agent_id,
                            "name": "Compressed weather",
                            "prompt": "private compressed instructions",
                        },
                    ]
                return [{
                    "id": "job-failed",
                    "profile": agent_id,
                    "name": "Research digest",
                    "prompt": "private scheduled instructions",
                }]

            async def _session_detail(self, session_id, agent_id):
                self.session_detail_coordinates.append((session_id, agent_id))
                return {
                    "compression-tip-0001": {
                        "id": "compression-tip-0001",
                        "source": "cron",
                        "model_config": {},
                        "parent_session_id": "cron_job-compressed_20260815_120200",
                        "started_at": 1_788_000_120,
                    },
                    "cron_job-compressed_20260815_120200": {
                        "id": "cron_job-compressed_20260815_120200",
                        "source": "cron",
                        "parent_session_id": None,
                        "ended_at": 1_788_000_119,
                        "end_reason": "compression",
                    },
                }[session_id]

            async def _session_messages(
                self, stored_id, agent_id, *, include_compacted=False
            ):
                self.history_coordinates.append(
                    (stored_id, agent_id, include_compacted)
                )
                if stored_id == "compression-tip-0001":
                    result = "The compressed run is ready."
                elif agent_id == "default":
                    result = "Bring an umbrella after 4 PM."
                else:
                    return {"messages": [{
                        "role": "assistant",
                        "content": "PRIVATE MODEL HANDOFF",
                        "display_content": "The source rejected the final request.",
                        "display_kind": "compaction_summary",
                        "_compressed_summary": True,
                    }]}
                return {"messages": [
                    {"role": "system", "content": "private system content"},
                    {"role": "user", "content": "private scheduled prompt"},
                    {"role": "tool", "content": "private tool result"},
                    {
                        "role": "assistant",
                        "content": result,
                        "reasoning_content": "private reasoning",
                        "tool_calls": [{"private": True}],
                    },
                ]}

        backend = _Backend()
        result = asyncio.run(backend.dashboard_load({"schemaVersion": 2}))

        self.assertEqual(result, {
            "schemaVersion": 2,
            "events": [
                {
                    "eventId": "event-job-completed",
                    "type": "job.completed",
                    "profile": "default",
                    "sessionId": "cron_job-completed_20260815_120000",
                    "approvalId": None,
                    "taskId": "job-completed",
                    "detail": {
                        "agent_name": "Gordie",
                        "title": "Morning weather",
                        "job_id": "job-completed",
                        "task_id": "job-completed",
                        "status": "completed",
                        "summary": "Bring an umbrella after 4 PM.",
                    },
                    "createdAt": 1_788_000_000,
                    "isRead": False,
                    "isPinned": True,
                },
                {
                    "eventId": "event-job-failed",
                    "type": "job.failed",
                    "profile": "research",
                    "sessionId": "cron_job-failed_20260815_120100",
                    "approvalId": None,
                    "taskId": "job-failed",
                    "detail": {
                        "agent_name": "Researcher",
                        "title": "Research digest",
                        "job_id": "job-failed",
                        "task_id": "job-failed",
                        "status": "failed",
                        "summary": "The source rejected the final request.",
                    },
                    "createdAt": 1_788_000_060,
                    "isRead": True,
                    "isPinned": False,
                },
                {
                    "eventId": "event-job-compressed",
                    "type": "job.completed",
                    "profile": "default",
                    "sessionId": "compression-tip-0001",
                    "approvalId": None,
                    "taskId": "job-compressed",
                    "detail": {
                        "agent_name": "Gordie",
                        "title": "Compressed weather",
                        "job_id": "job-compressed",
                        "task_id": "job-compressed",
                        "status": "completed",
                        "summary": "The compressed run is ready.",
                    },
                    "createdAt": 1_788_000_120,
                    "isRead": False,
                    "isPinned": False,
                },
            ],
        })
        self.assertEqual(backend.cron_profiles, ["default", "research"])
        self.assertEqual(backend.history_coordinates, [
            ("cron_job-completed_20260815_120000", "default", True),
            ("cron_job-failed_20260815_120100", "research", True),
            ("compression-tip-0001", "default", True),
        ])
        self.assertEqual(backend.session_detail_coordinates, [
            ("compression-tip-0001", "default"),
            ("cron_job-compressed_20260815_120200", "default"),
        ])
        serialized = repr(result)
        for private in (
            "private scheduled instructions",
            "private system content",
            "private scheduled prompt",
            "private tool result",
            "private reasoning",
            "PRIVATE MODEL HANDOFF",
        ):
            self.assertNotIn(private, serialized)

    def test_cron_identity_rejects_fork_and_cross_surface_compression_edges(self) -> None:
        parent_id = "cron_job-original_20260815_120000"

        class _Backend(HermesWorkspaceBackend):
            def __init__(self, child):
                super().__init__(service=SimpleNamespace(store=object()))
                self.child = child

            async def _session_detail(self, session_id, agent_id):
                self.assert_agent = agent_id
                if session_id == "candidate-child":
                    return {"id": session_id, **self.child}
                return {
                    "id": parent_id,
                    "source": "cron",
                    "parent_session_id": None,
                    "ended_at": 100,
                    "end_reason": "compression",
                }

        cases = (
            {
                "source": "cron",
                "model_config": {"_branched_from": parent_id},
                "parent_session_id": parent_id,
                "started_at": 101,
            },
            {
                "source": "desktop",
                "model_config": {},
                "parent_session_id": parent_id,
                "started_at": 101,
            },
        )
        for child in cases:
            with self.subTest(child=child), self.assertRaises(WorkspaceControlError):
                asyncio.run(
                    _Backend(child)._canonical_cron_job_id(
                        "candidate-child",
                        "default",
                    )
                )

    def test_dashboard_load_v2_omits_completion_with_missing_or_malformed_enrichment(self) -> None:
        class _Store:
            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                pass

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                pass

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                pass

            def list_events(self, *, limit, offset):
                if offset:
                    return []
                return [
                    {
                        "event_id": "event-completion",
                        "type": "job.completed",
                        "profile": "default",
                        "session_id": "cron_job-123_20260815_120000",
                        "job_id": "job-123",
                        "task_id": None,
                        "approval_id": None,
                        "detail": {},
                        "created_at": 1_788_000_000,
                        "is_read": False,
                        "is_pinned": False,
                    },
                    {
                        "event_id": "event-message",
                        "type": "channel.message",
                        "profile": "default",
                        "session_id": None,
                        "approval_id": None,
                        "detail": {"message": "Still visible"},
                        "created_at": 1_788_000_001,
                        "is_read": False,
                        "is_pinned": False,
                    },
                ]

        class _Backend(HermesWorkspaceBackend):
            def __init__(self, catalog, history):
                super().__init__(
                    service=SimpleNamespace(store=_Store()),
                    clock=lambda: 1_788_003_600,
                    clarify_timeout=lambda: 3_600,
                )
                self.catalog = catalog
                self.history = history

            async def _cron_list(self, agent_id):
                if isinstance(self.catalog, Exception):
                    raise self.catalog
                return self.catalog

            async def _session_messages(self, *args, **kwargs):
                if isinstance(self.history, Exception):
                    raise self.history
                return self.history

        cases = (
            ([], {"messages": [{"role": "assistant", "content": "result"}]}),
            ({"not": "a list"}, {"messages": []}),
            ([{"id": "job-123", "name": "Morning weather"}], {"messages": "bad"}),
            ([{"id": "job-123", "name": "Morning weather"}], {"messages": [
                {"role": "assistant", "content": "not final"},
                {"role": "tool", "content": "private tool result"},
            ]}),
            ([{"id": "job-123", "name": "Morning weather"}], {"messages": [{
                "role": "assistant",
                "content": "PRIVATE MODEL HANDOFF",
                "display_content": None,
                "display_kind": "hidden",
                "_compressed_summary": True,
            }]}),
            (RuntimeError("catalog unavailable"), {"messages": []}),
            ([{"id": "job-123", "name": "Morning weather"}], RuntimeError("history unavailable")),
        )
        for catalog, history in cases:
            with self.subTest(catalog=catalog, history=history):
                result = asyncio.run(
                    _Backend(catalog, history).dashboard_load({"schemaVersion": 2})
                )
                self.assertEqual(
                    [event["eventId"] for event in result["events"]],
                    ["event-message"],
                )

    def test_dashboard_load_v2_preserves_validated_weather_with_valid_until(self) -> None:
        from datetime import datetime, timezone
        from loopdy_plugin.generative_ui import render_v2_envelope

        payload = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures"
                / "generative_ui_v2"
                / "valid-weather.json"
            ).read_text(encoding="utf-8")
        )
        payload["provenance"]["valid_until"] = "2026-08-22T01:00:00Z"
        card = render_v2_envelope(
            "loopdy_render_weather_forecast",
            payload,
            now=datetime(2026, 8, 22, tzinfo=timezone.utc),
            profile="default",
            session_id="stored-session",
        )

        class _Store:
            def dismiss_gateway_lifecycle_events(self, *, dismissed_at):
                pass

            def dismiss_inactive_approval_events(self, *, now, dismissed_at):
                pass

            def dismiss_expired_attention(self, created_before, *, dismissed_at):
                pass

            def list_events(self, *, limit, offset):
                if offset:
                    return []
                return [{
                    "event_id": "event-weather",
                    "type": "channel.message",
                    "profile": "default",
                    "session_id": "stored-session",
                    "approval_id": None,
                    "detail": {"generative_ui": card},
                    "created_at": 1_788_000_000,
                    "is_read": False,
                    "is_pinned": False,
                }]

        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=_Store()),
            clock=lambda: 1_788_003_600,
            clarify_timeout=lambda: 3_600,
        )
        result = asyncio.run(backend.dashboard_load({"schemaVersion": 2}))

        self.assertEqual(
            result["events"][0]["detail"]["generative_ui"],
            card,
        )

    def test_dashboard_event_state_is_exact_and_store_bound(self) -> None:
        class _Store:
            def __init__(self):
                self.state = None

            def set_event_state(self, event_id, *, is_read, is_pinned):
                self.state = (event_id, is_read, is_pinned)
                return event_id == "event-0001"

        store = _Store()
        backend = HermesWorkspaceBackend(service=SimpleNamespace(store=store))

        result = asyncio.run(backend.dashboard_set_event_state({
            "eventId": "event-0001",
            "isRead": True,
            "isPinned": False,
        }))

        self.assertEqual(store.state, ("event-0001", True, False))
        self.assertEqual(result, {
            "eventId": "event-0001",
            "isRead": True,
            "isPinned": False,
        })
        with self.assertRaises(WorkspaceControlError):
            asyncio.run(backend.dashboard_set_event_state({
                "eventId": "event-0001",
                "isRead": 1,
                "isPinned": False,
            }))

    def test_dashboard_bulk_all_and_approval_response_are_store_bound(self) -> None:
        class _Store:
            def __init__(self):
                self.dismissed = []
                self.responded = []

            def list_events(self, *, limit, offset):
                return (
                    [{"event_id": "event-0001"}, {"event_id": "event-0002"}]
                    if offset == 0
                    else []
                )

            def dismiss_events(self, **kwargs):
                self.dismissed.append(kwargs)
                return len(tuple(kwargs.get("event_ids", ())))

            def get_approval(self, approval_id):
                return {
                    "approval_id": approval_id,
                    "request_digest": "digest-0001",
                    "allowed_choices": ["once", "session", "always", "deny"],
                    "event_id": "event-0001",
                    "status": "pending",
                    "choice": None,
                    "expires_at": 1_788_010_000,
                }

            def get_event(self, event_id):
                return {
                    "event_id": event_id,
                    "type": "approval.required",
                    "profile": "default",
                    "session_id": "session-0001",
                    "approval_id": "approval-0001",
                    "detail": {
                        "summary": "Run the test suite?",
                        "command": "private",
                        "interaction": {
                            "schemaVersion": 1,
                            "type": "approval",
                            "requestId": "approval-0001",
                            "expiresAt": 1_788_010_000,
                            "allowedChoices": ["once", "session", "always", "deny"],
                        },
                    },
                    "created_at": 1_788_000_000,
                }

            def respond_approval(self, approval_id, choice):
                self.responded.append((approval_id, choice))
                return True

        store = _Store()
        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=store),
            clock=lambda: 1_788_000_500,
        )

        dismissed = asyncio.run(backend.dashboard_dismiss_events({"all": True}))
        self.assertEqual(dismissed, {"dismissed": 2})
        self.assertEqual(tuple(store.dismissed[0]["event_ids"]), ("event-0001", "event-0002"))

        loaded = asyncio.run(backend.approvals_load({"approvalId": "approval-0001"}))
        self.assertEqual(loaded["approval"]["requestDigest"], "digest-0001")
        self.assertEqual(
            loaded["event"]["detail"]["interaction"]["allowedChoices"],
            ["once", "session", "always", "deny"],
        )
        self.assertNotIn("command", repr(loaded))

        responded = asyncio.run(backend.approvals_respond({
            "approvalId": "approval-0001",
            "requestDigest": "digest-0001",
            "choice": "session",
        }))
        self.assertEqual(store.responded, [("approval-0001", "session")])
        self.assertEqual(responded, {
            "accepted": True,
            "approvalId": "approval-0001",
            "choice": "session",
        })

    def test_clarification_response_is_bound_to_live_event_and_pending_hermes_request(
        self,
    ) -> None:
        class _Store:
            def __init__(self):
                self.dismissed = []

            def get_event(self, event_id):
                return {
                    "event_id": event_id,
                    "type": "attention.required",
                    "profile": "default",
                    "session_id": "opaque-link-chat-1",
                    "approval_id": None,
                    "detail": {
                        "kind": "clarify",
                        "request_id": "clarify-actual-1",
                        "session_key": "loopdy:gordie:opaque-link-chat-1",
                        "question": "Choose one",
                        "expires_at": "1788000600",
                        "interaction": {
                            "schemaVersion": 1,
                            "type": "clarify",
                            "requestId": "clarify-actual-1",
                            "expiresAt": 1_788_000_600,
                            "allowsCustomResponse": True,
                            "questions": [{
                                "id": "q0",
                                "question": "Choose one",
                                "choices": ["A", "B"],
                                "multiSelect": False,
                                "allowsCustomResponse": True,
                            }],
                        },
                    },
                    "created_at": 1_788_000_000,
                    "dismissed_at": None,
                    "is_read": False,
                    "is_pinned": False,
                }

            def dismiss_event(self, event_id):
                self.dismissed.append(event_id)
                return True

        store = _Store()
        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=store),
            clock=lambda: 1_788_000_500,
        )
        pending = SimpleNamespace(clarify_id="clarify-actual-1")
        projected = _event_projection(store.get_event("event-clarify-1"))
        self.assertEqual(
            projected["detail"]["interaction"]["requestId"],
            "clarify-actual-1",
        )
        self.assertEqual(
            projected["detail"]["interaction"]["questions"][0]["choices"],
            ["A", "B"],
        )
        with (
            patch(
                "tools.clarify_gateway.get_pending_for_session",
                return_value=pending,
            ) as get_pending,
            patch(
                "tools.clarify_gateway.resolve_gateway_clarify",
                return_value=True,
            ) as resolve,
        ):
            response = asyncio.run(backend.clarifications_respond({
                "eventId": "event-clarify-1",
                "clarifyId": "clarify-actual-1",
                "response": "A",
            }))

        get_pending.assert_called_once_with(
            "loopdy:gordie:opaque-link-chat-1", include_choice_prompts=True
        )
        resolve.assert_called_once_with("clarify-actual-1", "A")
        self.assertEqual(store.dismissed, ["event-clarify-1"])
        self.assertEqual(response, {
            "accepted": True,
            "eventId": "event-clarify-1",
            "clarifyId": "clarify-actual-1",
        })

    def test_clarification_response_rejects_expired_or_stale_requests(self) -> None:
        class _Store:
            def get_event(self, event_id):
                return {
                    "event_id": event_id,
                    "type": "attention.required",
                    "profile": "default",
                    "session_id": "session-key-1",
                    "approval_id": None,
                    "detail": {
                        "kind": "clarify",
                        "request_id": "clarify-actual-1",
                        "question": "Choose one",
                        "expires_at": "1788000400",
                        "interaction": {"type": "clarify"},
                    },
                    "created_at": 1_788_000_000,
                    "dismissed_at": None,
                    "is_read": False,
                    "is_pinned": False,
                }

        backend = HermesWorkspaceBackend(
            service=SimpleNamespace(store=_Store()),
            clock=lambda: 1_788_000_500,
        )
        with patch(
            "tools.clarify_gateway.resolve_gateway_clarify",
            return_value=True,
        ) as resolve:
            with self.assertRaises(WorkspaceConflictError):
                asyncio.run(backend.clarifications_respond({
                    "eventId": "event-clarify-1",
                    "clarifyId": "clarify-actual-1",
                    "response": "A",
                }))
        resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
