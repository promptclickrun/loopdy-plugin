from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from loopdy_plugin.attachments import AttachmentStore


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class _Service:
    def health(self):
        return {"ready": True}


class _WorkspaceGit:
    def capabilities(self):
        return {}


class AttachmentApiTests(unittest.TestCase):
    def test_resolve_and_download_use_opaque_profile_scoped_contract(self) -> None:
        module_name = "loopdy_attachment_api_for_test"
        spec = importlib.util.spec_from_file_location(
            module_name,
            PLUGIN_ROOT / "dashboard" / "plugin_api.py",
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        assert spec.loader is not None
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "chart.png"
            image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
            module._service = _Service()
            module._workspace_git_service = _WorkspaceGit()
            module._attachment_store = AttachmentStore(root / "attachments.sqlite3")
            app = FastAPI()
            app.include_router(module.router)
            client = TestClient(app)

            capabilities = client.get("/capabilities").json()
            self.assertTrue(capabilities["capabilities"]["native_agent_attachments"])
            self.assertEqual(capabilities["agent_attachments"]["schema_version"], 1)

            response = client.post(
                "/attachments/resolve",
                json={
                    "profile": "default",
                    "session_id": "session-1",
                    "items": [{"id": "row-1", "text": f"Ready.\nMEDIA:{image}"}],
                },
            )
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            attachment = payload["items"][0]["attachments"][0]
            self.assertNotIn(str(root), json.dumps(payload))

            download = client.get(f"/attachments/{attachment['id']}?profile=default")
            self.assertEqual(download.status_code, 200)
            self.assertEqual(download.content, image.read_bytes())
            self.assertEqual(download.headers["content-type"], "image/png")
            self.assertIn("chart.png", download.headers["content-disposition"])
            self.assertEqual(
                client.get(f"/attachments/{attachment['id']}?profile=other").status_code,
                404,
            )

    def test_malformed_resolve_and_unknown_download_fail_closed(self) -> None:
        module_name = "loopdy_attachment_api_invalid_for_test"
        spec = importlib.util.spec_from_file_location(
            module_name,
            PLUGIN_ROOT / "dashboard" / "plugin_api.py",
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        assert spec.loader is not None
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            module._attachment_store = AttachmentStore(Path(directory) / "attachments.sqlite3")
            app = FastAPI()
            app.include_router(module.router)
            client = TestClient(app)

            self.assertEqual(
                client.post(
                    "/attachments/resolve",
                    json={"profile": "default", "session_id": "session-1", "items": [{"id": "x"}]},
                ).status_code,
                422,
            )
            self.assertEqual(client.get(f"/attachments/{'0' * 32}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
