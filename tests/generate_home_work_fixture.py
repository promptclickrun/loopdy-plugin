"""Generate credential-free native contract bytes through the real plugin path.

Run from the plugin root with a temporary HERMES_HOME:
python -m tests.generate_home_work_fixture /absolute/path/to/output.json
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

from loopdy_plugin.hooks import normalize_hook
from loopdy_plugin.link_contracts import WorkspaceRequest, workspace_result
from loopdy_plugin.store import LoopdyStore
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceController
from tests.test_registration import _Service


def generate() -> dict:
    with tempfile.TemporaryDirectory() as directory:
        service = _Service()
        service.store = LoopdyStore(Path(directory) / "events.sqlite3")
        payloads = [
            ("on_session_end", dict(platform="loopdy", session_id="contract-user", turn_id="contract-user-turn", completed=True)),
            ("on_session_end", dict(platform="cron", session_id="cron_contract-job_20260906_120000", turn_id="contract-cron-turn", completed=True)),
            ("subagent_stop", dict(parent_session_id="contract-user", child_session_id="contract-child", child_subagent_id="contract-delegation", child_status="completed", child_goal="Review accessibility")),
        ]
        for hook, payload in payloads:
            event = normalize_hook(hook, profile="default", **payload)
            assert event is not None
            service.store.record_event(event)
        request = WorkspaceRequest(request_id="home-contract-request", operation="dashboard.load", payload={}, sent_at=int(time.time()))
        controller = WorkspaceController(backend=HermesWorkspaceBackend(service=service))
        payload = asyncio.run(controller.execute(request))
        assert len(payload["events"]) == 3
        return workspace_result(request=request, status="completed", payload=payload, sent_at=int(time.time()))


if __name__ == "__main__":
    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(generate(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(destination)
