"""Exercise tool observation through stock Hermes dispatch, without live data."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hermes_cli.plugins import PluginManager
from test_registration import _Context, _Service
from loopdy_plugin.registration import register


class RuntimeContext(_Context):
    def __init__(self):
        super().__init__()
        self.manager = PluginManager()

    def register_hook(self, name, callback):
        super().register_hook(name, callback)
        self.manager._hooks.setdefault(name, []).append(callback)

    def register_middleware(self, kind, callback):
        self.manager._middleware.setdefault(kind, []).append(callback)


class ToolObserverTests(unittest.TestCase):
    def context(self, observe):
        context = RuntimeContext()
        managed = SimpleNamespace(
            observe=observe, owns_alert=lambda **kw: False,
            producer_loaded=lambda *a, **kw: None, close=lambda: None,
        )
        context.service = _Service()
        with patch('loopdy_plugin.managed_notifications.get_managed_notifications', return_value=managed):
            register(context, service=context.service)
        self.addCleanup(context.unload)
        return context

    @staticmethod
    def dispatch(context, call_id):
        payload = dict(tool_name='bigfeels_remember', args={'content': 'Synthetic test'},
                       session_id='synthetic-session', turn_id='synthetic-turn',
                       tool_call_id=call_id, profile_name='personal')
        rewrites = context.manager.invoke_middleware('tool_request', **payload)
        if any(isinstance(item, dict) and 'args' in item for item in rewrites):
            raise AssertionError('Notification observer changed tool arguments')
        decisions = context.manager.invoke_hook('pre_tool_call', **payload)
        if any(isinstance(item, dict) and item.get('action') == 'block' for item in decisions):
            return {'blocked': decisions}
        return {'saved': call_id}

    def test_parallel_save_is_not_blocked_by_another_notification_observer(self):
        entered, release = threading.Event(), threading.Event()
        observations = []

        def observe(hook, **payload):
            if hook != 'pre_tool_call':
                return
            observations.append((payload['tool_call_id'], payload['profile']))
            if payload['tool_call_id'] == 'first':
                entered.set()
                if not release.wait(5):
                    raise AssertionError('Test did not release observer')

        context = self.context(observe)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.dispatch, context, 'first')
            try:
                self.assertTrue(entered.wait(2), 'Real registered observer never ran')
                second = pool.submit(self.dispatch, context, 'second').result(timeout=2)
                self.assertEqual(second, {'saved': 'second'})
            finally:
                release.set()
            self.assertEqual(first.result(timeout=2), {'saved': 'first'})
        self.assertCountEqual(observations, [('first', 'personal'), ('second', 'personal')])

    def test_notification_failure_does_not_veto_save_or_leak_details(self):
        def observe(hook, **payload):
            raise RuntimeError('synthetic-private-detail')
        context = self.context(observe)
        with self.assertLogs(level='WARNING') as captured:
            self.assertEqual(self.dispatch(context, 'failure'), {'saved': 'failure'})
        self.assertNotIn('synthetic-private-detail', '\n'.join(captured.output))

    def test_real_policy_gate_still_blocks_the_tool(self):
        context = self.context(lambda *a, **kw: None)
        context.register_hook('pre_tool_call', lambda **kw: {'action': 'block', 'message': 'Policy denial'})
        result = self.dispatch(context, 'denied')
        self.assertEqual(result, {'blocked': [{'action': 'block', 'message': 'Policy denial'}]})

    def test_modern_tool_request_preserves_clarification_activity_and_arguments(self):
        observations = []
        context = self.context(lambda hook, **kw: observations.append((hook, kw)))
        payload = dict(tool_name='clarify', args={'questions': [{'question': 'Choose'}]},
                       session_id='synthetic-session', turn_id='synthetic-turn',
                       tool_call_id='clarification', profile_name='personal')
        before = repr(payload)
        self.assertEqual(context.manager.invoke_middleware('tool_request', **payload), [])
        self.assertEqual(repr(payload), before)
        self.assertEqual(observations[0][0], 'pre_tool_call')
        self.assertEqual(observations[0][1]['tool_call_id'], 'clarification')
        self.assertEqual(observations[0][1]['profile'], 'personal')
        # The legacy activity producer still emits the waiting phase once.
        self.assertEqual(len(context.service.events), 1)
        kind, update = context.service.events[0]
        self.assertEqual(kind, 'live-activity')
        self.assertEqual(update['phase'], 'waiting')

    def test_tool_start_observers_do_not_register_as_policy_gates(self):
        context = self.context(lambda *a, **kw: None)
        self.assertNotIn('pre_tool_call', context.manager._hooks)
        self.assertTrue(context.manager._middleware.get('tool_request'))


if __name__ == '__main__':
    unittest.main()
