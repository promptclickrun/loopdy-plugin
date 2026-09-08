"""Optional Wiki integration on the existing authenticated workspace boundary.

Constructing the factory does no I/O. Only explicit Wiki requests or the host
Wiki CLI instantiate services. All devices/profiles share one captured directory
and one service lock; neither caller payload nor selected profile chooses it.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .wiki_contract import (
    WIKI_OPERATIONS, available_wiki_operations, bounded_result, validate_payload,
)
from .wiki_service import WikiService, WikiServiceError


def authority_id(config: Any) -> str:
    """Opaque pairing generation; never retain/output raw account-key material."""
    if (config is None or not isinstance(config.device_id, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,96}", config.device_id) is None
            or type(config.authorization_epoch) is not int or config.authorization_epoch < 1
            or type(config.account_key) is not bytes or len(config.account_key) != 32
            or not isinstance(config.base_url, str) or not config.base_url):
        raise WikiServiceError("WIKI_OWNER_REQUIRED", "Wiki requires a current paired host")
    return hashlib.sha256(json.dumps([
        "loopdy-wiki-authority-v1", config.base_url, config.device_id,
        config.authorization_epoch, hashlib.sha256(config.account_key).hexdigest(),
    ], separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WikiRequestContext:
    target_host_id: str | None
    device_id: str
    authority_id: str | None
    sender_epoch: int | None


class WikiTransport:
    def __init__(self, *, state_dir: Path, config_getter: Callable[[], Any],
                 protected_roots: tuple[Path, ...] = ()):
        # Do not resolve a profile or root from a request. Capture host home once.
        self.state_dir = Path(state_dir)
        self.config_getter = config_getter
        self.protected_roots = protected_roots
        self._service: WikiService | None = None
        self._service_authority: str | None = None
        self._lock = threading.Lock()

    def _current(self):
        try:
            config = self.config_getter()
            return config, authority_id(config)
        except WikiServiceError:
            raise
        except Exception:
            raise WikiServiceError("WIKI_OWNER_REQUIRED", "Wiki requires a current paired host") from None

    def check_context(self, context: WikiRequestContext | None) -> None:
        config, owner = self._current()
        if (not isinstance(context, WikiRequestContext)
                or context.target_host_id != config.device_id
                or context.authority_id != owner
                or type(context.sender_epoch) is not int
                # The relay authenticates this epoch against the sending device.
                # Host and mobile authorization generations are independent;
                # the current host generation is already bound by authority_id.
                or context.sender_epoch < 1
                or not isinstance(context.device_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,96}", context.device_id) is None
                or context.device_id == config.device_id):
            raise WikiServiceError("WIKI_OWNER_REQUIRED", "Wiki request owner is missing or stale")

    def host_service(self) -> WikiService:
        """Host CLI entry, never exposed as an operation to a remote device."""
        _, owner = self._current()
        with self._lock:
            if self._service is None or self._service_authority != owner:
                def check():
                    if self._current()[1] != owner:
                        raise WikiServiceError("WIKI_OWNER_CHANGED", "Wiki pairing changed during the request")
                self._service = WikiService(self.state_dir, authority_id=owner, owner_check=check,
                                            protected_roots=self.protected_roots)
                self._service_authority = owner
            return self._service

    def execute(self, operation: str, payload: dict, *, context: WikiRequestContext | None) -> dict:
        self.check_context(context)
        if operation not in WIKI_OPERATIONS:
            raise WikiServiceError("INVALID_REQUEST", "Wiki operation is unsupported")
        if operation not in available_wiki_operations():
            raise WikiServiceError(
                "CAPABILITY_UNSUPPORTED", "Secure Wiki traversal is unavailable on this platform"
            )
        try:
            p = validate_payload(operation, payload)
        except ValueError:
            raise WikiServiceError("INVALID_REQUEST", "Wiki request is invalid") from None
        service = self.host_service()
        # The factory may have awaited its initialization lock across an owner
        # change. Never adopt the new owner for an already admitted old request.
        self.check_context(context)
        assert context is not None
        if service._authority_id != context.authority_id:
            raise WikiServiceError("WIKI_OWNER_CHANGED", "Wiki pairing changed during the request")
        identity = {"profile_id": p["agentId"], "device_id": context.device_id}
        if operation == "wiki.roots":
            result = service.roots(**identity)
        elif operation == "wiki.connect":
            # This capability comes from the checked encrypted Link context,
            # never a payload flag or caller-supplied account identifier.
            result = service.connect(p["folderPath"], **identity, account_authorized=True)
        elif operation == "wiki.resolve":
            result = service.resolve(p["folderPath"], **identity)
        elif operation == "wiki.list":
            result = service.list_directory(p["wikiId"], **identity, path=p["path"],
                offset=p["offset"], limit=p["limit"], query=p["query"], revision=p.get("revision"))
        elif operation in {"wiki.read", "wiki.image"}:
            method = service.read_file if operation == "wiki.read" else service.read_image
            result = method(p["wikiId"], **identity, path=p["path"], offset=p["offset"],
                            limit=p["limit"], revision=p.get("revision"))
        elif operation == "wiki.search":
            from .wiki_search import WikiSearch
            result = WikiSearch(service).search(p, device_id=context.device_id)
        else:
            from .wiki_uploads import WikiUploads
            uploads = WikiUploads(service)
            handler = {"wiki.save.begin": uploads.begin, "wiki.save.chunk": uploads.chunk,
                       "wiki.save.commit": uploads.commit, "wiki.save.status": uploads.status}[operation]
            result = handler(p, device_id=context.device_id)
        self.check_context(context)
        return bounded_result(result)


def production_factory(*, host_home: Path, config_getter: Callable[[], Any]) -> WikiTransport:
    return WikiTransport(state_dir=Path(host_home) / "plugin-data" / "loopdy" / "wiki",
                         config_getter=config_getter, protected_roots=(Path(host_home),))
