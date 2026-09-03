from __future__ import annotations

import unittest
from pathlib import Path

from tools.plugin_guard import scan_plugin, should_allow_plugin_install


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SOURCE = "promptclickrun/loopdy-plugin"


class PluginSecurityScanTests(unittest.TestCase):
    def test_stock_scanner_allows_settings_force_install(self) -> None:
        result = scan_plugin(PLUGIN_ROOT, source=PLUGIN_SOURCE)
        allowed, reason = should_allow_plugin_install(result, force=True)
        findings = "\n".join(
            f"{finding.severity}: {finding.pattern_id} "
            f"({finding.file}:{finding.line}) {finding.match}"
            for finding in result.findings
        )

        self.assertIn(result.verdict, {"safe", "caution"}, findings)
        self.assertIs(allowed, True, reason)


if __name__ == "__main__":
    unittest.main()
