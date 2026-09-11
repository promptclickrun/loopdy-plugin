from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class PortabilityTests(unittest.TestCase):
    def test_manifest_explicitly_supports_all_hermes_desktop_operating_systems(self) -> None:
        import yaml

        manifest = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))

        self.assertEqual(manifest["kind"], "platform")
        self.assertEqual(manifest["version"], "2.11.2")
        self.assertEqual(set(manifest["platforms"]), {"linux", "macos", "windows"})

    def test_link_runtime_coordinates_never_depend_on_posix_path_syntax(self) -> None:
        from loopdy_plugin import adapter

        windows_home = PureWindowsPath("C:/Users/fixture/.hermes")
        expected = windows_home / "plugin-data" / "loopdy" / "loopdy.sqlite3"

        with patch.object(adapter, "get_hermes_home", return_value=windows_home):
            actual = adapter.data_path()

        self.assertEqual(actual, expected)
        self.assertEqual(
            str(actual),
            r"C:\Users\fixture\.hermes\plugin-data\loopdy\loopdy.sqlite3",
        )

    def test_store_lock_uses_native_windows_locking_without_importing_fcntl(self) -> None:
        from loopdy_plugin import store

        calls: list[tuple[int, int]] = []
        fake_msvcrt = types.SimpleNamespace(
            LK_NBLCK=11,
            LK_UNLCK=12,
            locking=lambda _descriptor, mode, count: calls.append((mode, count)),
        )
        descriptor, path = tempfile.mkstemp(prefix="loopdy-portability-")
        try:
            with (
                patch.object(store.os, "name", "nt"),
                patch.dict(sys.modules, {"msvcrt": fake_msvcrt}),
            ):
                store._lock_file_descriptor(descriptor)
                store._unlock_file_descriptor(descriptor)
        finally:
            os.close(descriptor)
            Path(path).unlink(missing_ok=True)

        self.assertEqual(calls, [(11, 1), (12, 1)])


if __name__ == "__main__":
    unittest.main()
