import unittest
from unittest.mock import patch

from loopdy_plugin.link_contracts import parse_workspace_request, workspace_capabilities
from loopdy_plugin.wiki_contract import available_wiki_operations
from loopdy_plugin.workspace_files import WorkspaceFilesError, WorkspaceFilesService


class WikiWireTests(unittest.TestCase):
    @unittest.skipUnless(available_wiki_operations(), "Requires secure descriptor-relative traversal")
    def test_optional_wiki_roots_request_has_a_real_wire_contract(self):
        value = {'version': 1, 'type': 'workspace.request', 'requestId': 'wiki-request-fixture-0001', 'operation': 'wiki.roots', 'payload': {'agentId': 'default'}, 'sentAt': 1}
        try:
            request = parse_workspace_request(value)
        except ValueError:
            self.fail('Negotiated Wiki roots requests need a supported wire operation')
        self.assertEqual(request.operation, 'wiki.roots')
        self.assertEqual(request.payload, {'agentId': 'default'})

    def test_unsupported_host_does_not_advertise_wiki(self):
        unsupported = WorkspaceFilesError(
            "CAPABILITY_UNSUPPORTED", "Secure workspace traversal is unavailable on this platform"
        )
        with patch.object(
            WorkspaceFilesService, "_require_secure_platform", side_effect=unsupported
        ):
            capabilities = workspace_capabilities()
        self.assertNotIn("wiki.v1", capabilities["features"])
        self.assertFalse(any(operation.startswith("wiki.") for operation in capabilities["operations"]))


if __name__ == '__main__':
    unittest.main()
