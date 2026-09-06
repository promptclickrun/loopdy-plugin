from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import AsyncMock, patch

from loopdy_plugin import plugin_update
from loopdy_plugin.host_runtime import InstalledHermesVersion
from loopdy_plugin.link_contracts import WorkspaceRequest, workspace_result
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceControlError, WorkspaceController


def legacy_profiles(*, catalog=False):
    module = ModuleType('hermes_cli.profiles')
    for name, value in {
        'get_profile_dir': lambda name: Path('/fixture'),
        'profile_exists': lambda name: True,
        'read_profile_meta': lambda path: {},
    }.items():
        setattr(module, name, value)
    if catalog:
        setattr(module, 'list_profile_names', lambda: [])
    return module


class HostRuntimeDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.backend = HermesWorkspaceBackend(service=object(), attachment_store=object(), clock=lambda: 1788000000)
        self.version = patch.object(InstalledHermesVersion, 'get', new=AsyncMock(return_value='0.20.4'))
        self.version.start()
        self.addCleanup(self.version.stop)

    async def test_missing_profile_catalog_has_actionable_gateway_error(self):
        with patch.dict(sys.modules, {'hermes_cli.profiles': legacy_profiles()}):
            try:
                await self.backend.agents_list({})
            except WorkspaceControlError as error:
                self.assertEqual(error.code, 'hermes_capability_missing')
                self.assertIn('Update Hermes', str(error))
            except ImportError as error:
                self.fail(f'Profile compatibility escaped as an unclassified {type(error).__name__}')
            else:
                self.fail('Missing profile support must not look like an empty catalog')
        status = await self.backend.host_runtime_status({})
        self.assertEqual(status['compatibility']['state'], 'incompatible')
        self.assertEqual(status['compatibility']['unavailableOperations'], ['agents.list'])

    async def test_diagnostics_does_not_require_successful_agent_enumeration(self):
        with patch.object(self.backend, '_profile_records', side_effect=AssertionError('must not enumerate')):
            request = WorkspaceRequest('workspace-diagnostics-0001', 'host_runtime.status', {}, 1788000000)
            payload = await WorkspaceController(backend=self.backend).execute(request)
            wire = workspace_result(request=request, status='completed', payload=payload, sent_at=1788000000)
        self.assertEqual(wire['payload']['compatibility']['state'], 'unknown')
        self.assertEqual(wire['payload']['hermes'], {
            'cliVersion': '0.20.4', 'runningVersion': None, 'updateState': 'unknown',
            'updateCheckedAt': None, 'restartState': 'unknown',
        })

    async def test_success_clears_failure_and_unrelated_failure_is_unknown(self):
        with patch.dict(sys.modules, {'hermes_cli.profiles': legacy_profiles()}):
            with self.assertRaises(WorkspaceControlError):
                await self.backend.agents_list({})
        with patch.dict(sys.modules, {'hermes_cli.profiles': legacy_profiles(catalog=True)}):
            self.assertEqual(await self.backend.agents_list({}), {'agents': []})
        self.assertEqual((await self.backend.host_runtime_status({}))['compatibility']['state'], 'compatible')
        with patch.object(self.backend, '_profile_records', side_effect=PermissionError('private path')):
            with self.assertRaises(PermissionError):
                await self.backend.agents_list({})
        self.assertEqual((await self.backend.host_runtime_status({}))['compatibility']['state'], 'unknown')

    async def test_unrelated_import_is_not_claimed_to_be_known_capability(self):
        module = legacy_profiles(catalog=True)
        delattr(module, 'read_profile_meta')
        with patch.dict(sys.modules, {'hermes_cli.profiles': module}):
            with self.assertRaises(ImportError):
                await self.backend.agents_list({})
        self.assertEqual((await self.backend.host_runtime_status({}))['compatibility']['state'], 'unknown')

    async def test_activation_uses_current_process_not_journal(self):
        for installed, active, expected in [('a'*40, 'b'*40, 'required'), ('a'*40, 'a'*40, 'not_required'), ('', 'a'*40, 'unknown')]:
            with self.subTest(expected=expected), patch.object(plugin_update, '_metadata_revision', return_value=installed), patch.object(plugin_update, 'LOADED_REVISION', active):
                status = await self.backend.host_runtime_status({})
                self.assertEqual(status['plugin']['restartState'], expected)
                self.assertEqual(status['runtimeId'], plugin_update.RUNTIME_ID)
                self.assertEqual(status['plugin']['activeRevision'], active)
                self.assertEqual(status['hermes']['restartState'], 'unknown')

    async def test_failed_discovery_still_negotiates_diagnostics_and_legacy_stays_exact(self):
        from gateway.config import PlatformConfig
        from loopdy_plugin.adapter import LoopdyAdapter
        from loopdy_plugin.link_client import InboundLinkWorkspaceRequest
        if __package__:
            from .test_adapter import _LinkClient, _Service
        else:
            from test_adapter import _LinkClient, _Service

        from gateway.platform_registry import PlatformEntry, platform_registry
        platform_registry.register(PlatformEntry(name='loopdy', label='Loopdy',
                                                adapter_factory=lambda config: None, check_fn=lambda: True))
        link = _LinkClient()
        with patch('loopdy_plugin.adapter.load_runtime_config', return_value=None):
            adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=_Service(),
                                    link_client=link, workspace_controller=WorkspaceController(backend=self.backend))
        with patch.dict(sys.modules, {'hermes_cli.profiles': legacy_profiles()}):
            for device, payload in [('modern-fixture', {'linkProtocol': 1}), ('legacy-fixture', {})]:
                await adapter.receive_link_payload(InboundLinkWorkspaceRequest(
                    request=WorkspaceRequest('workspace-failed-probe-0001', 'agents.list', payload, 1788000000),
                    sender_device_id=device,
                ))
                result = link.payloads[-1]
                self.assertEqual(result['code'], 'hermes_capability_missing')
                self.assertEqual(result['status'], 'failed')
                if device == 'modern-fixture':
                    self.assertIn('host_runtime.status', result['capabilities']['operations'])
                else:
                    self.assertNotIn('capabilities', result)
        await adapter.receive_link_payload(InboundLinkWorkspaceRequest(
            request=WorkspaceRequest('workspace-status-probe-0001', 'host_runtime.status', {}, 1788000000),
            sender_device_id='modern-fixture',
        ))
        self.assertEqual(link.payloads[-1]['status'], 'completed')
        self.assertEqual(link.payloads[-1]['payload']['compatibility']['state'], 'incompatible')

    async def test_client_cannot_supply_commands_or_source(self):
        for payload in [{'command': 'anything'}, {'hostId': 'other'}, {'url': 'https://example.test'}, {'profile': 'other'}]:
            with self.subTest(payload=payload), self.assertRaises(WorkspaceControlError):
                await self.backend.host_runtime_status(payload)


class InstalledVersionTests(unittest.IsolatedAsyncioTestCase):
    async def test_caches_known_and_unknown_observations(self):
        for observed in ['0.21.0', None]:
            with self.subTest(observed=observed), patch.object(InstalledHermesVersion, '_read', new=AsyncMock(return_value=observed)) as probe:
                reader = InstalledHermesVersion()
                self.assertEqual(await reader.get(), observed)
                self.assertEqual(await reader.get(), observed)
                probe.assert_awaited_once()

    async def test_cli_output_is_bounded_and_never_exposes_raw_text(self):
        class Process:
            returncode = 0
            def __init__(self, output):
                self.stdout = asyncio.StreamReader()
                self.stdout.feed_data(output)
                self.stdout.feed_eof()
            async def wait(self):
                return 0
        for output, expected in [
            (b'Hermes Agent v0.21.0 (date)\nInstall directory: private\n', '0.21.0'),
            (b'private error\n', None),
            (b'Hermes Agent v0.21.0\n' + b'x'*4096, None),
        ]:
            with self.subTest(expected=expected), patch('asyncio.create_subprocess_exec', new=AsyncMock(return_value=Process(output))) as spawn:
                self.assertEqual(await InstalledHermesVersion._read(), expected)
                self.assertEqual(spawn.call_args.args, ('hermes', '--version'))
