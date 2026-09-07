"""Explicit host-local Wiki grant administration, registered by Loopdy's CLI.

Run on the profile that owns the paired host, not the target document profile.
The --profile-id flag is grant policy only; it cannot choose a state directory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .wiki_service import WikiServiceError
from .wiki_transport import WikiTransport


def setup_wiki_cli(actions: Any) -> None:
    wiki = actions.add_parser("wiki", help="Manage separate host-authorized Wiki grants")
    commands = wiki.add_subparsers(dest="loopdy_wiki_action", required=True)
    grant = commands.add_parser("grant", help="Authorize an exact Wiki root for the paired account or explicit devices")
    grant.add_argument("wiki_id")
    grant.add_argument("--root", required=True)
    grant.add_argument("--label", required=True)
    grant.add_argument("--profile-id", required=True)
    scope = grant.add_mutually_exclusive_group(required=True)
    scope.add_argument("--device", dest="device_ids", action="append")
    scope.add_argument("--account", action="store_true",
                       help="Allow all authenticated devices on this paired Loopdy account")
    grant.add_argument("--access", choices=("read-only", "read-write"), required=True)
    grant.add_argument("--source-kind", choices=("files", "generated", "mirror", "export"), required=True)
    grant.add_argument("--yes", action="store_true", help="Confirm the explicit grant policy")
    revoke = commands.add_parser("revoke", help="Revoke a Wiki grant, retaining recovery evidence")
    revoke.add_argument("wiki_id")
    revoke.add_argument("--yes", action="store_true", help="Confirm revocation")
    commands.add_parser("list", help="List this paired host's grant policy without document content")


def handle_wiki_cli(args: Any, *, transport: WikiTransport) -> None:
    try:
        action = args.loopdy_wiki_action
        if action not in {"grant", "revoke", "list"}:
            raise WikiServiceError("INVALID_REQUEST", "Unknown Wiki administration command")
        if action in {"grant", "revoke"} and args.yes is not True:
            raise WikiServiceError("INVALID_REQUEST", "Pass --yes to confirm the Wiki policy change")
        service = transport.host_service()
        if action == "grant":
            result = service.grant(
                args.wiki_id, root=Path(args.root), label=args.label, profile_id=args.profile_id,
                device_ids=tuple(args.device_ids or ()), writable=args.access == "read-write",
                source_kind=args.source_kind, access_scope="account" if args.account else "device",
            )
        elif action == "revoke":
            result = service.revoke(args.wiki_id)
        else:
            result = service.list_grants()
    except WikiServiceError as error:
        print(json.dumps(error.envelope(), ensure_ascii=True, sort_keys=True))
        raise SystemExit(1) from None
    except Exception:
        error = WikiServiceError("WIKI_UNAVAILABLE", "Wiki administration could not be completed")
        print(json.dumps(error.envelope(), ensure_ascii=True, sort_keys=True))
        raise SystemExit(1) from None
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
