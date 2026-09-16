"""Tests for host-side AI coding tool discovery and local usage reporting."""

from __future__ import annotations

import json
import os
import stat
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from loopdy_plugin import provider_usage
from loopdy_plugin.provider_usage import discover_providers, get_provider_usage


def _make_binary(bin_dir: Path, name: str, version: str) -> None:
    script = bin_dir / name
    script.write_text(f"#!/bin/sh\necho '{version}'\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


class ProviderDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        self.old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(self.bin) + os.pathsep + self.old_path

    def tearDown(self) -> None:
        os.environ["PATH"] = self.old_path
        self.tmp.cleanup()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def test_discovers_installed_and_authenticated_tool(self) -> None:
        _make_binary(self.bin, "claude", "1.2.3 (Claude Code)")
        (self.home / ".claude.json").write_text("{}", encoding="utf-8")
        (self.home / ".claude").mkdir(exist_ok=True)
        (self.home / ".claude" / ".credentials.json").write_text(
            '{"claudeAiOauth": {"accessToken": "sk-ant-fake-secret-123"}}',
            encoding="utf-8",
        )
        payload = discover_providers(home=self.home, include_usage=False)
        entry = next(p for p in payload["providers"] if p["id"] == "claude_code")
        self.assertTrue(entry["installed"])
        self.assertEqual(entry["version"], "1.2.3 (Claude Code)")
        self.assertTrue(entry["authenticated"])
        self.assertTrue(entry["config_present"])

    def test_auth_file_contents_never_leak(self) -> None:
        _make_binary(self.bin, "codex", "codex-cli 0.1.0")
        secret = "sk-proj-fake-secret-value-abcdef123456"
        (self.home / ".codex").mkdir()
        (self.home / ".codex" / "auth.json").write_text(
            json.dumps({"OPENAI_API_KEY": secret}), encoding="utf-8"
        )
        payload = discover_providers(home=self.home, include_usage=True)
        rendered = json.dumps(payload)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("sk-proj-fake", rendered)

    def test_missing_tool_reports_not_installed(self) -> None:
        payload = discover_providers(home=self.home, include_usage=False)
        entry = next(p for p in payload["providers"] if p["id"] == "gemini_cli")
        self.assertFalse(entry["installed"])
        self.assertIsNone(entry["version"])
        self.assertFalse(entry["authenticated"])

    def test_claude_transcript_usage_sums_windowed_tokens(self) -> None:
        _make_binary(self.bin, "claude", "1.0.0")
        recent = self._now_iso()
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        _write_jsonl(
            self.home / ".claude" / "projects" / "proj" / "sess.jsonl",
            [
                {
                    "type": "assistant",
                    "timestamp": recent,
                    "message": {
                        "model": "claude-sonnet-4-5",
                        "usage": {
                            "input_tokens": 100,
                            "output_tokens": 50,
                            "cache_read_input_tokens": 1000,
                            "cache_creation_input_tokens": 200,
                        },
                    },
                },
                {
                    "type": "assistant",
                    "timestamp": old,
                    "message": {
                        "model": "claude-sonnet-4-5",
                        "usage": {"input_tokens": 99999, "output_tokens": 99999},
                    },
                },
                {"type": "user", "timestamp": recent, "message": {"content": "hi"}},
                "not json at all",
            ],
        )
        usage = get_provider_usage("claude_code", home=self.home, usage_days=7)
        self.assertTrue(usage["available"])
        self.assertEqual(usage["source"], "local_transcripts")
        self.assertEqual(usage["input_tokens"], 100)
        self.assertEqual(usage["output_tokens"], 50)
        self.assertEqual(usage["cache_read_input_tokens"], 1000)
        self.assertEqual(usage["total_tokens"], 1350)

    def test_codex_rollout_usage_sums_deltas(self) -> None:
        _make_binary(self.bin, "codex", "0.2.0")
        recent = self._now_iso()
        _write_jsonl(
            self.home / ".codex" / "sessions" / "2026" / "09" / "16" / "rollout-1.jsonl",
            [
                {
                    "timestamp": recent,
                    "payload": {
                        "type": "token_count",
                        "info": {
                            "last_token_usage": {
                                "input_tokens": 10,
                                "cached_input_tokens": 5,
                                "output_tokens": 20,
                            },
                            "total_token_usage": {
                                "input_tokens": 10,
                                "cached_input_tokens": 5,
                                "output_tokens": 20,
                            },
                        },
                    },
                },
                {
                    "timestamp": recent,
                    "payload": {
                        "type": "token_count",
                        "info": {
                            "last_token_usage": {
                                "input_tokens": 30,
                                "cached_input_tokens": 0,
                                "output_tokens": 40,
                            },
                            "total_token_usage": {
                                "input_tokens": 40,
                                "cached_input_tokens": 5,
                                "output_tokens": 60,
                            },
                        },
                    },
                },
            ],
        )
        usage = get_provider_usage("codex", home=self.home, usage_days=7)
        self.assertTrue(usage["available"])
        self.assertEqual(usage["source"], "local_sessions")
        # Deltas only: 10+30 input, 20+40 output. Totals must not double count.
        self.assertEqual(usage["input_tokens"], 40)
        self.assertEqual(usage["output_tokens"], 60)

    def test_usage_unavailable_without_ledger(self) -> None:
        usage = get_provider_usage("claude_code", home=self.home, usage_days=7)
        self.assertFalse(usage["available"])
        self.assertIn("reason", usage)

    def test_provider_without_local_source_reports_reason(self) -> None:
        usage = get_provider_usage("copilot_cli", home=self.home)
        self.assertFalse(usage["available"])
        self.assertIn("organization API", usage["reason"])

    def test_unknown_provider_id(self) -> None:
        usage = get_provider_usage("not_a_tool", home=self.home)
        self.assertFalse(usage["available"])
        self.assertIn("unknown provider", usage["reason"])

    def test_usage_days_clamped(self) -> None:
        payload = discover_providers(home=self.home, include_usage=False, usage_days=999)
        self.assertEqual(payload["usage_window_days"], 30)

    def test_one_bad_provider_does_not_break_discovery(self) -> None:
        payload = discover_providers(home="/nonexistent-home-xyz", include_usage=True)
        self.assertEqual(len(payload["providers"]), len(provider_usage._PROVIDERS))
        self.assertEqual(payload["schema"], "loopdy.provider_discovery")


class ProviderToolRegistrationTests(unittest.TestCase):
    def test_discovery_tool_registered_with_bounded_schema(self) -> None:
        from loopdy_plugin.tools import register

        class _Ctx:
            profile_name = "default"

            def __init__(self) -> None:
                self.tools: dict = {}
                self.schemas: dict = {}

            def register_tool(self, *, name, handler, schema, **_kwargs) -> None:
                self.tools[name] = handler
                self.schemas[name] = schema

        ctx = _Ctx()
        register(ctx)
        self.assertIn("loopdy_provider_discovery", ctx.tools)
        schema = ctx.schemas["loopdy_provider_discovery"]
        self.assertEqual(schema["parameters"]["properties"]["usage_days"]["maximum"], 30)
        result = json.loads(ctx.tools["loopdy_provider_discovery"]({}))
        self.assertEqual(result["schema"], "loopdy.provider_discovery")
        ids = [p["id"] for p in result["providers"]]
        self.assertIn("claude_code", ids)
        self.assertIn("codex", ids)
        self.assertIn("copilot_cli", ids)

    def test_handler_rejects_bad_arguments(self) -> None:
        from loopdy_plugin.tools import _provider_discovery_handler

        with self.assertRaises(ValueError):
            _provider_discovery_handler("nope")
        with self.assertRaises(ValueError):
            _provider_discovery_handler({"usage_days": 99})
        with self.assertRaises(ValueError):
            _provider_discovery_handler({"include_usage": "yes"})


if __name__ == "__main__":
    unittest.main()
