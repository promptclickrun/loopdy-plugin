from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient


class NativeNotificationEnrollmentTests(unittest.TestCase):
    def test_mounted_router_exposes_notification_identity_without_link_pairing(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = directory
            try:
                path = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
                spec = importlib.util.spec_from_file_location("notification_bootstrap_test", path)
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                app = FastAPI()
                app.include_router(module.router)
                with TestClient(app) as client:
                    response = client.get("/notifications/capabilities")
                    self.assertEqual(response.status_code, 200)
                    body = response.json()
                    self.assertEqual(body["version"], 1)
                    self.assertTrue(body["managedEnrollmentSupported"])
                    self.assertTrue(body["hostKeyId"])
                    self.assertTrue(body["hostPublicKey"])
                    self.assertNotIn("private", response.text.lower())
            finally:
                if previous is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = previous
                sys.modules.pop("notification_bootstrap_test", None)


if __name__ == "__main__":
    unittest.main()
