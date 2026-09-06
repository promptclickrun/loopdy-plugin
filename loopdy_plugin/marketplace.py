"""Validated Loopdy Marketplace packaging and host-side installation.

Marketplace content is untrusted. This module validates approved source metadata,
then delegates quarantine, scanning, collision refusal, and atomic publication to
Hermes' supported Skills Hub CLI. It never accepts a caller-provided URL or
filesystem destination and never executes an installed script.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import unicodedata
from dataclasses import dataclass
from inspect import isawaitable
from pathlib import PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlsplit


_AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
_CARD_TEMPLATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CAPABILITY = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,63}$")
_SKILL_PATH = re.compile(
    r"^(?:references|scripts|templates|assets)/[A-Za-z0-9][A-Za-z0-9._/-]{0,191}$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SAFE_ROOTS = frozenset({"assets", "references", "scripts", "templates"})
_FORBIDDEN_SKILL_SUFFIXES = (
    ".zip",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".7z",
    ".rar",
    ".gz",
    ".bz2",
    ".xz",
    ".dmg",
    ".pkg",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".wasm",
)
_MAX_SKILL_PACKAGE_BYTES = 1_500_000
_MAX_SKILL_DECODED_BYTES = 2 * 1024 * 1024
_MAX_SKILL_FILE_BYTES = 100_000
_MAX_SKILL_FILES = 20
_MAX_DRAFT_READBACK_BYTES = 2 * 1024 * 1024 + 128 * 1024
CARD_TEMPLATE_CAPABILITY = "cards-templates-v1"
MARKETPLACE_SKILL_CAPABILITY = "marketplace-skills-hub-v1"
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class MarketplaceInstallError(RuntimeError):
    """A marketplace release could not be installed safely."""


class MarketplacePublishError(RuntimeError):
    """A selected source could not be prepared as a private draft."""


@dataclass(frozen=True)
class MarketplaceSkillPackage:
    name: str
    skill_md: str
    files: Mapping[str, str]

    @property
    def all_files(self) -> dict[str, bytes]:
        return {
            "SKILL.md": self.skill_md.encode("utf-8"),
            **{path: content.encode("utf-8") for path, content in self.files.items()},
        }


@dataclass(frozen=True)
class MarketplaceHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class MarketplaceGatewayClient:
    """Fixed-origin signed gateway client for marketplace private operations."""

    def __init__(
        self,
        *,
        config: Any,
        trust_keys: Mapping[str, Any],
        transport: Any | None = None,
    ):
        self.config = config
        self.trust_keys = {
            str(key): _ed25519_public_key(value) for key, value in trust_keys.items()
        }
        self.transport = transport or MarketplaceHTTPTransport()

    async def redeem_and_fetch_skill(self, payload: dict[str, Any]) -> bytes:
        request = _install_request(payload)
        approval_id = request["approvalId"]
        redeem_path = f"/v1/marketplace/install-approvals/{approval_id}/redeem"
        redeem_body = _canonical_json_bytes(
            {
                "agentId": request["agentId"],
                "itemId": request["itemId"],
                "version": request["version"],
                "sha256": request["sha256"],
                "requestId": request["requestId"],
            }
        )
        headers = self.config.signed_headers(
            method="POST", path=redeem_path, body=redeem_body.decode("utf-8")
        )
        headers.update(
            {"content-type": "application/json", "accept": "application/json"}
        )
        redeem = await self._request(
            method="POST",
            path=redeem_path,
            headers=headers,
            body=redeem_body,
            max_bytes=16_384,
        )
        _successful_json_response(redeem, label="install approval redemption")

        manifest_path = (
            f"/v1/marketplace/items/{request['itemId']}/versions/"
            f"{request['version']}/manifest"
        )
        manifest_response = await self._request(
            method="GET",
            path=manifest_path,
            headers={"accept": "application/json"},
            body=None,
            max_bytes=128 * 1024,
        )
        envelope = _successful_json_response(
            manifest_response, label="release manifest"
        )
        listing, artifact_path = _verified_skill_manifest(
            envelope=envelope,
            trust_keys=self.trust_keys,
            item_id=request["itemId"],
            version=request["version"],
            sha256=request["sha256"],
        )
        artifact = await self._request(
            method="GET",
            path=artifact_path,
            headers={"accept": "application/json"},
            body=None,
            max_bytes=_MAX_SKILL_PACKAGE_BYTES,
        )
        _require_success(artifact, label="skill artifact")
        _require_json_content_type(artifact)
        if len(artifact.body) != listing["byteCount"]:
            raise MarketplaceInstallError("Marketplace skill artifact byte count is invalid")
        if not hmac.compare_digest(
            hashlib.sha256(artifact.body).hexdigest(), request["sha256"]
        ):
            raise MarketplaceInstallError("Marketplace skill artifact digest is invalid")
        parsed = parse_skill_package(artifact.body)
        if (
            any(path.startswith("scripts/") for path in parsed.files)
            and "skill.scripts" not in listing["requiredCapabilities"]
        ):
            raise MarketplaceInstallError(
                "Marketplace skill scripts are missing the skill.scripts capability"
            )
        return artifact.body

    async def create_draft(
        self,
        *,
        kind: str,
        metadata: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        if kind not in {"theme", "card", "skill"}:
            raise MarketplacePublishError("Marketplace draft kind is invalid")
        normalized_metadata = _wire_metadata(metadata)
        if not isinstance(idempotency_key, str) or not _RESOURCE_ID.fullmatch(
            idempotency_key
        ):
            raise MarketplacePublishError("Marketplace idempotency key is invalid")
        body = _canonical_json_bytes(
            {
                "kind": kind,
                "metadata": normalized_metadata,
                "idempotencyKey": idempotency_key,
            }
        )
        response = await self._private_request(
            method="POST",
            path="/v1/marketplace/drafts",
            body=body,
            max_bytes=128 * 1024,
        )
        return _successful_json_response(response, label="draft creation")

    async def upload_draft(
        self,
        *,
        draft_id: str,
        revision: int,
        package: bytes,
    ) -> dict[str, Any]:
        _draft_resource_id(draft_id)
        _draft_revision({"revision": revision}, allow_zero=True)
        if not isinstance(package, bytes) or not 0 < len(package) <= 2 * 1024 * 1024:
            raise MarketplacePublishError("Marketplace draft package is invalid")
        try:
            package.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MarketplacePublishError("Marketplace draft package must be UTF-8 JSON") from exc
        path = f"/v1/marketplace/drafts/{draft_id}/artifact"
        response = await self._private_request(
            method="PUT",
            path=path,
            body=package,
            max_bytes=128 * 1024,
            extra_headers={"x-loopdy-draft-revision": str(revision)},
        )
        return _successful_json_response(response, label="draft upload")

    async def get_draft(self, *, draft_id: str) -> dict[str, Any]:
        _draft_resource_id(draft_id)
        response = await self._private_request(
            method="GET",
            path=f"/v1/marketplace/drafts/{draft_id}",
            body=b"",
            max_bytes=_MAX_DRAFT_READBACK_BYTES,
        )
        return _successful_json_response(response, label="draft readback")

    async def _private_request(
        self,
        *,
        method: str,
        path: str,
        body: bytes,
        max_bytes: int,
        extra_headers: Mapping[str, str] | None = None,
    ) -> MarketplaceHTTPResponse:
        try:
            signed_body = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MarketplacePublishError("Marketplace request body must be UTF-8") from exc
        headers = self.config.signed_headers(
            method=method,
            path=path,
            body=signed_body,
        )
        headers["accept"] = "application/json"
        if method in {"POST", "PUT"}:
            headers["content-type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        return await self._request(
            method=method,
            path=path,
            headers=headers,
            body=body if method in {"POST", "PUT"} else None,
            max_bytes=max_bytes,
        )

    async def _request(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
    ) -> MarketplaceHTTPResponse:
        result = self.transport.request(
            method=method,
            url=self.config.base_url + path,
            headers=dict(headers),
            body=body,
            max_bytes=max_bytes,
        )
        if isawaitable(result):
            result = await result
        if not isinstance(result, MarketplaceHTTPResponse):
            raise MarketplaceInstallError("Marketplace transport returned an invalid response")
        if len(result.body) > max_bytes:
            raise MarketplaceInstallError("Marketplace response exceeded its size limit")
        return result


class MarketplaceHTTPTransport:
    """Small no-redirect HTTPS transport with bounded response reads."""

    async def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
    ) -> MarketplaceHTTPResponse:
        return await asyncio.to_thread(
            self._request_sync,
            method=method,
            url=url,
            headers=headers,
            body=body,
            max_bytes=max_bytes,
        )

    @staticmethod
    def _request_sync(
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
    ) -> MarketplaceHTTPResponse:
        import urllib.error
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, response_headers, newurl):
                return None

        request = urllib.request.Request(
            url=url,
            data=body,
            headers=dict(headers),
            method=method,
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=15) as response:
                raw = response.read(max_bytes + 1)
                return MarketplaceHTTPResponse(
                    status=int(response.status),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=raw,
                )
        except urllib.error.HTTPError as error:
            raw = error.read(min(max_bytes, 16_384) + 1)
            return MarketplaceHTTPResponse(
                status=int(error.code),
                headers={key.lower(): value for key, value in error.headers.items()},
                body=raw,
            )
        except (OSError, urllib.error.URLError) as exc:
            raise MarketplaceInstallError("Marketplace service is unavailable") from exc


def load_marketplace_trust_keys(
    values: Mapping[str, str] | None = None,
) -> dict[str, bytes]:
    """Load deployment-configured public trust anchors; never a listing key."""

    import os

    source = os.environ if values is None else values
    encoded = str(source.get("LOOPDY_MARKETPLACE_TRUSTED_ED25519_KEYS") or "").strip()
    if not encoded:
        return {}
    try:
        value = json.loads(encoded, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, MarketplaceInstallError) as exc:
        raise MarketplaceInstallError("Marketplace trust configuration is invalid") from exc
    if not isinstance(value, dict) or not 1 <= len(value) <= 8:
        raise MarketplaceInstallError("Marketplace trust configuration is invalid")
    result: dict[str, bytes] = {}
    for key_id, key_value in value.items():
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise MarketplaceInstallError("Marketplace trust configuration is invalid")
        decoded = _decoded_standard_base64(
            key_value, label="trust key", maximum=32
        )
        if len(decoded) != 32:
            raise MarketplaceInstallError("Marketplace trust configuration is invalid")
        result[key_id] = decoded
    return result


def build_marketplace_gateway_client(
    config: Any | None,
    *,
    values: Mapping[str, str] | None = None,
    transport: Any | None = None,
) -> MarketplaceGatewayClient | None:
    if config is None:
        return None
    keys = load_marketplace_trust_keys(values)
    if not keys:
        return None
    return MarketplaceGatewayClient(
        config=config,
        trust_keys=keys,
        transport=transport,
    )


class HermesHubCLI:
    """Bounded argv-only client for Hermes' supported profile-aware Skills Hub CLI."""

    def __init__(self, *, executable: str | None = None, runner: Any | None = None):
        self.executable = executable or shutil.which("hermes") or ""
        self.runner = runner or subprocess.run

    async def validate_profile(self, agent_id: str) -> None:
        result = await asyncio.to_thread(self._run, ["profile", "show", agent_id])
        if result.returncode != 0:
            raise MarketplaceInstallError("Marketplace target agent does not exist")

    async def contains(self, agent_id: str, skill_name: str, *, source: str = "hub") -> bool:
        if source not in {"all", "hub"}:
            raise MarketplaceInstallError("Hermes Hub status source is invalid")
        result = await asyncio.to_thread(
            self._run,
            ["-p", agent_id, "skills", "list", "--source", source],
        )
        if result.returncode != 0:
            raise MarketplaceInstallError("Hermes Hub skill status is unavailable")
        output = _ANSI_ESCAPE.sub("", str(result.stdout or ""))
        names = _installed_skill_names(output)
        return skill_name in names

    async def install(self, agent_id: str, identifier: str, skill_name: str) -> None:
        result = await asyncio.to_thread(
            self._run,
            ["-p", agent_id, "skills", "install", identifier, "--yes"],
        )
        output = _ANSI_ESCAPE.sub(
            "", f"{str(result.stdout or '')}\n{str(result.stderr or '')}"
        )
        if result.returncode != 0:
            raise MarketplaceInstallError("Hermes Hub installation failed")
        lowered = output.casefold()
        if "already installed" in lowered:
            raise MarketplaceInstallError(
                "A skill with this name already exists; it was not replaced"
            )
        if "blocked" in lowered:
            raise MarketplaceInstallError("Hermes Hub scanner blocked installation")
        installed_rows = [
            line.strip()
            for line in output.splitlines()
            if re.fullmatch(rf"Installed:\s+{re.escape(skill_name)}", line.strip())
        ]
        if len(installed_rows) == 1:
            return
        raise MarketplaceInstallError("Hermes Hub rejected the skill installation")

    def _run(self, arguments: list[str]) -> Any:
        if not self.executable:
            raise MarketplaceInstallError("Hermes CLI is unavailable")
        try:
            environment = os.environ.copy()
            environment["COLUMNS"] = "1024"
            return self.runner(
                [self.executable, *arguments],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=90,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MarketplaceInstallError("Hermes CLI request failed") from exc


def _installed_skill_names(output: str) -> set[str]:
    expected_header = ["Name", "Category", "Source", "Trust", "Status"]
    saw_header = False
    names: list[str] = []
    for line in output.splitlines():
        if line.startswith("┃") and line.endswith("┃"):
            cells = [value.strip() for value in line[1:-1].split("┃")]
            if cells == expected_header:
                saw_header = True
            continue
        if not line.startswith("│") or not line.endswith("│"):
            continue
        cells = [value.strip() for value in line[1:-1].split("│")]
        if len(cells) != 5 or not cells[0] or cells[4] not in {"enabled", "disabled"}:
            raise MarketplaceInstallError("Hermes Hub status output is ambiguous")
        if "…" in cells[0] or "..." in cells[0] or not _SKILL_NAME.fullmatch(cells[0]):
            raise MarketplaceInstallError("Hermes Hub status output is ambiguous")
        names.append(cells[0])
    footer = re.search(
        r"^(\d+) hub-installed, (\d+) builtin, (\d+) local\s+—\s+"
        r"(\d+) enabled, (\d+) disabled$",
        output,
        flags=re.MULTILINE,
    )
    if not saw_header or footer is None:
        raise MarketplaceInstallError("Hermes Hub status output is ambiguous")
    source_total = sum(int(footer.group(index)) for index in (1, 2, 3))
    state_total = sum(int(footer.group(index)) for index in (4, 5))
    if source_total != len(names) or state_total != len(names) or len(names) != len(set(names)):
        raise MarketplaceInstallError("Hermes Hub status output is ambiguous")
    return set(names)


class MarketplaceSkillInstaller:
    """Install an approved immutable release through one selected profile's Skills Hub."""

    def __init__(
        self,
        *,
        store: Any,
        release_client: Any,
        hub_client: Any | None = None,
        marketplace_base_url: str | None = None,
    ):
        self.store = store
        self.release_client = release_client
        self.hub_client = hub_client or HermesHubCLI()
        self.marketplace_base_url = marketplace_base_url or str(
            getattr(getattr(release_client, "config", None), "base_url", "")
        )

    async def install(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = _install_request(payload)
        await self.hub_client.validate_profile(request["agentId"])
        receipt = self.store.get_marketplace_skill_install(
            profile=request["agentId"], item_id=request["itemId"]
        )
        if receipt is not None:
            if receipt.get("verificationMode") != "hermes_hub":
                raise MarketplaceInstallError(
                    "Legacy marketplace receipt cannot establish Hermes Hub installation"
                )
            same_release = receipt["version"] == request["version"] and hmac.compare_digest(
                receipt["sha256"], request["sha256"]
            )
            if not same_release:
                raise MarketplaceInstallError(
                    "A different release is already recorded; review the update before installing"
                )
            if await self.hub_client.contains(
                request["agentId"], receipt["skillName"], source="hub"
            ):
                return {
                    **_hub_receipt(receipt, installed=True),
                    "changed": False,
                }

        raw_package = await self.release_client.redeem_and_fetch_skill(dict(request))
        if not isinstance(raw_package, bytes):
            raise MarketplaceInstallError("Marketplace returned an invalid skill artifact")
        if not hmac.compare_digest(
            hashlib.sha256(raw_package).hexdigest(), request["sha256"]
        ):
            raise MarketplaceInstallError("Marketplace skill artifact digest does not match approval")
        package = parse_skill_package(raw_package)
        identifier = _marketplace_hub_identifier(
            self.marketplace_base_url,
            item_id=request["itemId"],
            version=request["version"],
            skill_name=package.name,
        )
        if await self.hub_client.contains(
            request["agentId"], package.name, source="all"
        ):
            raise MarketplaceInstallError(
                "A skill with this name already exists; it was not replaced"
            )
        await self.hub_client.install(request["agentId"], identifier, package.name)
        if not await self.hub_client.contains(
            request["agentId"], package.name, source="hub"
        ):
            raise MarketplaceInstallError("Hermes Hub did not report the installed skill")

        receipt = self.store.record_marketplace_skill_install(
            profile=request["agentId"],
            item_id=request["itemId"],
            version=request["version"],
            sha256=request["sha256"],
            skill_name=package.name,
            content_sha256=None,
            files={},
            request_id=request["requestId"],
            verification_mode="hermes_hub",
        )
        return {**_hub_receipt(receipt, installed=True), "changed": True}

    async def status(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = _status_request(payload)
        await self.hub_client.validate_profile(request["agentId"])
        receipt = self.store.get_marketplace_skill_install(
            profile=request["agentId"], item_id=request["itemId"]
        )
        if receipt is None:
            return {
                **request,
                "installed": False,
                "status": "not_installed",
                "verificationMode": "hermes_hub",
            }
        if receipt.get("verificationMode") != "hermes_hub":
            raise MarketplaceInstallError(
                "Legacy marketplace receipt cannot establish Hermes Hub installation"
            )
        present = await self.hub_client.contains(
            request["agentId"], receipt["skillName"], source="hub"
        )
        return _hub_receipt(receipt, installed=present)


def _hub_receipt(receipt: Mapping[str, Any], *, installed: bool) -> dict[str, Any]:
    return {
        "agentId": receipt["agentId"],
        "itemId": receipt["itemId"],
        "version": receipt["version"],
        # This digest describes the approved marketplace source artifact only.
        "sha256": receipt["sha256"],
        "skillName": receipt["skillName"],
        "installed": installed,
        "status": "installed" if installed else "missing",
        "verificationMode": "hermes_hub",
    }


def _marketplace_hub_identifier(
    base_url: str, *, item_id: str, version: int, skill_name: str
) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise MarketplaceInstallError("Marketplace Hub origin is invalid")
    origin = f"https://{parsed.netloc}"
    return (
        f"well-known:{origin}/.well-known/skills/marketplace/{item_id}/"
        f"versions/{version}/{skill_name}"
    )


class MarketplacePublisher:
    """Package one explicitly selected local item for private app review."""

    def __init__(
        self,
        *,
        agent_id: str,
        store: Any,
        attachment_store: Any | None,
        gateway_client: Any | None,
    ):
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise MarketplacePublishError("Marketplace source agent is invalid")
        self.agent_id = agent_id
        self.store = store
        self.attachment_store = attachment_store
        self.gateway_client = gateway_client

    async def prepare_upload(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            request = _publication_request(payload)
        except MarketplacePublishError as exc:
            return {
                "draftId": None,
                "revision": 0,
                "sha256": "",
                "validationState": "blocked",
                "findings": [
                    _finding("metadata_invalid", "blocking", str(exc))
                ],
                "reviewDestination": "Loopdy Marketplace > My Uploads",
            }
        if request["agentId"] != self.agent_id:
            return {
                "draftId": None,
                "revision": 0,
                "sha256": "",
                "validationState": "blocked",
                "findings": [
                    _finding(
                        "source_scope_invalid",
                        "blocking",
                        "The selected source does not belong to this Hermes agent",
                    )
                ],
                "reviewDestination": "Loopdy Marketplace > My Uploads",
            }
        findings: list[dict[str, str]] = _metadata_findings(request["metadata"])
        package = b""
        try:
            package = await asyncio.to_thread(
                self._selected_package,
                request["agentId"],
                request["kind"],
                request["sourceId"],
                request["metadata"]["requiredCapabilities"],
            )
        except MarketplacePublishError as exc:
            findings.append(
                _finding("source_invalid", "blocking", str(exc))
            )
        if package:
            findings.extend(
                _package_findings(
                    package,
                    kind=request["kind"],
                    required_capabilities=request["metadata"]["requiredCapabilities"],
                )
            )
        digest = hashlib.sha256(package).hexdigest() if package else ""
        result: dict[str, Any] = {
            "draftId": None,
            "revision": 0,
            "sha256": digest,
            "validationState": (
                "blocked"
                if any(item["severity"] == "blocking" for item in findings)
                else "valid"
            ),
            "findings": findings,
            "reviewDestination": "Loopdy Marketplace > My Uploads",
        }
        if request["validateOnly"] or result["validationState"] == "blocked":
            return result
        if self.gateway_client is None:
            return {
                **result,
                "validationState": "blocked",
                "findings": [
                    *findings,
                    _finding(
                        "marketplace_unavailable",
                        "blocking",
                        "Loopdy Link marketplace publishing is not configured",
                    ),
                ],
            }
        draft = await self.gateway_client.create_draft(
            kind=request["kind"],
            metadata=request["metadata"],
            idempotency_key=request["idempotencyKey"],
        )
        draft_id = _draft_id(draft)
        revision = _draft_revision(draft, allow_zero=True)
        await self.gateway_client.upload_draft(
            draft_id=draft_id,
            revision=revision,
            package=package,
        )
        readback = await self.gateway_client.get_draft(draft_id=draft_id)
        projected = _draft_readback(readback, expected_kind=request["kind"])
        if not hmac.compare_digest(projected["sha256"], digest):
            raise MarketplacePublishError(
                "Marketplace draft readback did not match the selected package"
            )
        return {
            **projected,
            "reviewDestination": "Loopdy Marketplace > My Uploads",
        }

    def _selected_package(
        self,
        agent_id: str,
        kind: str,
        source_id: str,
        required_capabilities: list[str],
    ) -> bytes:
        if kind == "card":
            if not _CARD_TEMPLATE_ID.fullmatch(source_id):
                raise MarketplacePublishError("Selected card identifier is invalid")
            getter = getattr(self.store, "get_card_template", None)
            if not callable(getter):
                raise MarketplacePublishError("Loopdy card template storage is unavailable")
            template = getter(profile=agent_id, template_id=source_id)
            if not isinstance(template, dict):
                raise MarketplacePublishError("Selected card template was not found")
            document = template.get("document")
            if not isinstance(document, dict) or document.get("data_sources") != []:
                raise MarketplacePublishError(
                    "Marketplace cards must use embedded values and no live data sources"
                )
            package = {
                "schemaVersion": 1,
                "kind": "card",
                "content": {"template": template},
            }
            return json.dumps(
                package,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        if kind == "skill":
            return _selected_skill_package(
                agent_id,
                source_id,
                required_capabilities=required_capabilities,
            )
        if kind == "theme":
            return _selected_theme_package(
                self.attachment_store, agent_id=agent_id, source_id=source_id
            )
        raise MarketplacePublishError("Marketplace source kind is invalid")


def _publication_request(payload: Any) -> dict[str, Any]:
    expected = {
        "agentId",
        "kind",
        "sourceId",
        "validateOnly",
        "metadata",
        "idempotencyKey",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise MarketplacePublishError("Marketplace publish request is invalid")
    agent_id = payload.get("agentId")
    kind = payload.get("kind")
    source_id = payload.get("sourceId")
    validate_only = payload.get("validateOnly")
    idempotency_key = payload.get("idempotencyKey")
    if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
        raise MarketplacePublishError("Selected agent is invalid")
    if kind not in {"theme", "card", "skill"}:
        raise MarketplacePublishError("Marketplace source kind is invalid")
    if (
        not isinstance(source_id, str)
        or not 1 <= len(source_id) <= 128
        or any(ord(character) < 32 for character in source_id)
    ):
        raise MarketplacePublishError("Selected source identifier is invalid")
    if type(validate_only) is not bool:
        raise MarketplacePublishError("validateOnly must be a boolean")
    if (
        not isinstance(idempotency_key, str)
        or not _RESOURCE_ID.fullmatch(idempotency_key)
    ):
        raise MarketplacePublishError("Marketplace idempotency key is invalid")
    metadata = _publication_metadata(payload.get("metadata"))
    return {
        "agentId": agent_id,
        "kind": kind,
        "sourceId": source_id,
        "validateOnly": validate_only,
        "metadata": metadata,
        "idempotencyKey": idempotency_key,
    }


def _publication_metadata(value: Any) -> dict[str, Any]:
    expected = {
        "title",
        "summary",
        "description",
        "tags",
        "publicAuthorName",
        "license",
        "declaredCapabilities",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise MarketplacePublishError("Marketplace publication metadata is invalid")
    title = _publication_text(value.get("title"), "title", 1, 80, trim=True)
    summary = _publication_text(value.get("summary"), "summary", 1, 240, trim=True)
    description = _publication_text(
        value.get("description"), "description", 0, 8_000, trim=False
    )
    author = _publication_text(
        value.get("publicAuthorName"), "public author name", 1, 80, trim=True
    )
    license_value = value.get("license")
    if not isinstance(license_value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}", license_value
    ):
        raise MarketplacePublishError("An explicit valid license is required")
    tags = _publication_string_list(value.get("tags"), "tags", 8, 24, ascii_only=False)
    capabilities = _publication_string_list(
        value.get("declaredCapabilities"),
        "declared capabilities",
        16,
        64,
        ascii_only=True,
        pattern=_CAPABILITY,
    )
    return {
        "name": title,
        "summary": summary,
        "description": description,
        "author": author,
        "license": license_value,
        "tags": tags,
        "requiredCapabilities": capabilities,
    }


def _wire_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "name",
        "summary",
        "description",
        "author",
        "license",
        "tags",
        "requiredCapabilities",
    }:
        raise MarketplacePublishError("Marketplace draft metadata is invalid")
    return _publication_metadata(
        {
            "title": value.get("name"),
            "summary": value.get("summary"),
            "description": value.get("description"),
            "publicAuthorName": value.get("author"),
            "license": value.get("license"),
            "tags": value.get("tags"),
            "declaredCapabilities": value.get("requiredCapabilities"),
        }
    )


def _publication_text(
    value: Any,
    label: str,
    minimum: int,
    maximum: int,
    *,
    trim: bool,
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (trim and value != value.strip())
    ):
        raise MarketplacePublishError(f"Marketplace {label} is invalid")
    return value


def _publication_string_list(
    value: Any,
    label: str,
    maximum_items: int,
    maximum_length: int,
    *,
    ascii_only: bool,
    pattern: re.Pattern[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise MarketplacePublishError(f"Marketplace {label} are invalid")
    result: list[str] = []
    normalized_items: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or not 1 <= len(item) <= maximum_length
            or item != item.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            or (ascii_only and not item.isascii())
            or (pattern is not None and not pattern.fullmatch(item))
        ):
            raise MarketplacePublishError(f"Marketplace {label} are invalid")
        normalized = unicodedata.normalize("NFKC", item).casefold()
        if normalized in normalized_items:
            raise MarketplacePublishError(f"Marketplace {label} must be unique")
        normalized_items.add(normalized)
        result.append(item)
    return result


def _finding(
    code: str,
    severity: str,
    message: str,
    path: str | None = None,
) -> dict[str, str]:
    result = {"code": code, "severity": severity, "message": message}
    if path:
        result["path"] = path[:512]
    return result


def _metadata_findings(metadata: Mapping[str, Any]) -> list[dict[str, str]]:
    from .sensitive import contains_sensitive_credential

    if contains_sensitive_credential(
        json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    ):
        return [
            _finding(
                "secret_detected",
                "blocking",
                "Possible credential material was detected in publication metadata",
            )
        ]
    return []


def _package_findings(
    package: bytes,
    *,
    kind: str,
    required_capabilities: list[str],
) -> list[dict[str, str]]:
    limits = {"theme": 2 * 1024 * 1024, "card": 128 * 1024, "skill": 1_500_000}
    findings: list[dict[str, str]] = []
    if len(package) > limits[kind]:
        findings.append(
            _finding(
                "package_too_large",
                "blocking",
                f"The selected {kind} package exceeds its upload limit",
            )
        )
    try:
        text = package.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(
            _finding("package_invalid", "blocking", "Marketplace packages must be UTF-8 JSON")
        )
        return findings
    from .sensitive import SECRET_PATH_RE, contains_sensitive_credential

    if kind != "skill" and contains_sensitive_credential(text):
        findings.append(
            _finding(
                "secret_detected",
                "blocking",
                "Possible credential material was detected in the selected content",
            )
        )
    if kind == "skill":
        try:
            skill = parse_skill_package(package)
        except MarketplaceInstallError as exc:
            findings.append(
                _finding("package_invalid", "blocking", str(exc))
            )
            return findings
        for path, content in skill.all_files.items():
            if SECRET_PATH_RE.search(path):
                findings.append(
                    _finding(
                        "secret_path_forbidden",
                        "blocking",
                        "Secret-bearing file paths cannot be published",
                        path,
                    )
                )
            if path.startswith("scripts/"):
                if "skill.scripts" in required_capabilities:
                    findings.append(
                        _finding(
                            "script_review_required",
                            "warning",
                            "Skill scripts require manual review and never run during installation",
                            path,
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            "script_capability_missing",
                            "blocking",
                            "Skill scripts require the skill.scripts capability",
                            path,
                        )
                    )
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError:
                findings.append(
                    _finding(
                        "binary_file_forbidden",
                        "blocking",
                        "Skill files must be UTF-8 text",
                        path,
                    )
                )
                continue
            if contains_sensitive_credential(decoded):
                findings.append(
                    _finding(
                        "secret_detected",
                        "blocking",
                        "Possible credential material was detected",
                        path,
                    )
                )
    return findings


def _selected_skill_package(
    _agent_id: str,
    source_id: str,
    *,
    required_capabilities: list[str],
) -> bytes:
    if not isinstance(source_id, str) or not _SKILL_NAME.fullmatch(source_id):
        raise MarketplacePublishError("Selected skill identifier is invalid")
    _ = required_capabilities
    raise MarketplacePublishError(
        "Marketplace skill publishing is unavailable because Hermes has no supported "
        "non-preprocessed raw skill export API"
    )


def _selected_theme_package(
    attachment_store: Any | None,
    *,
    agent_id: str,
    source_id: str,
) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{32}", source_id):
        raise MarketplacePublishError("Selected theme attachment identifier is invalid")
    reader = getattr(attachment_store, "read", None)
    if not callable(reader):
        raise MarketplacePublishError("Loopdy attachment storage is unavailable")
    attachment = reader(profile=agent_id, attachment_id=source_id)
    if not isinstance(attachment, dict):
        raise MarketplacePublishError("Selected theme attachment was not found")
    content = attachment.get("content")
    if (
        not isinstance(content, bytes)
        or not content
        or len(content) > 2 * 1024 * 1024
        or attachment.get("size") != len(content)
    ):
        raise MarketplacePublishError("Selected theme attachment is invalid")
    mime_type = str(attachment.get("mime_type") or "").split(";", 1)[0].lower()
    name = str(attachment.get("name") or "")
    if mime_type not in {"application/json", "text/json", "text/plain"} and not name.lower().endswith(".json"):
        raise MarketplacePublishError("Selected theme attachment must be JSON")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, MarketplaceInstallError) as exc:
        raise MarketplacePublishError("Selected theme attachment is invalid JSON") from exc
    if not isinstance(value, dict):
        raise MarketplacePublishError("Selected theme attachment is invalid")
    if set(value) == {"schemaVersion", "kind", "content"}:
        if value.get("schemaVersion") != 1 or value.get("kind") != "theme":
            raise MarketplacePublishError("Selected theme package is unsupported")
        package_content = value.get("content")
    elif set(value) == {"schemaVersion", "themes"}:
        themes = value.get("themes")
        if value.get("schemaVersion") != 1 or not isinstance(themes, list) or len(themes) != 1:
            raise MarketplacePublishError(
                "Select an attachment containing exactly one custom theme"
            )
        package_content = {"theme": themes[0]}
    else:
        package_content = {"theme": value}
    normalized = _theme_content(package_content)
    return json.dumps(
        {"schemaVersion": 1, "kind": "theme", "content": normalized},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _theme_content(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not {"theme"}.issubset(value) or set(value) - {
        "theme",
        "lightLogoBase64",
        "darkLogoBase64",
    }:
        raise MarketplacePublishError("Selected theme package content is invalid")
    theme = value.get("theme")
    if not isinstance(theme, dict) or set(theme) not in (
        {"id", "name", "font", "accentHex", "light", "dark"},
        {"id", "name", "description", "font", "accentHex", "light", "dark"},
    ):
        raise MarketplacePublishError("Selected theme fields are invalid")
    if any(key in theme for key in ("logo", "lightLogo", "darkLogo")):
        raise MarketplacePublishError(
            "Theme attachments must not contain local logo metadata"
        )
    identifier = theme.get("id")
    if not isinstance(identifier, str) or not _UUID.fullmatch(identifier):
        raise MarketplacePublishError("Selected theme identifier is invalid")
    _publication_text(theme.get("name"), "theme name", 1, 40, trim=True)
    if "description" in theme and theme.get("description") is not None:
        _publication_text(
            theme.get("description"), "theme description", 0, 120, trim=False
        )
    if theme.get("font") not in {
        "system",
        "rounded",
        "serif",
        "monospaced",
        "notoSans",
    }:
        raise MarketplacePublishError("Selected theme font is invalid")
    accent = theme.get("accentHex")
    if not isinstance(accent, str) or not re.fullmatch(r"[0-9A-Fa-f]{6}", accent):
        raise MarketplacePublishError("Selected theme accent color is invalid")
    _theme_palette(theme.get("light"))
    _theme_palette(theme.get("dark"))
    result: dict[str, Any] = {"theme": dict(theme)}
    for key in ("lightLogoBase64", "darkLogoBase64"):
        if key not in value:
            continue
        try:
            logo = _decoded_standard_base64(
                value.get(key), label="theme logo", maximum=1_000_000
            )
        except MarketplaceInstallError as exc:
            raise MarketplacePublishError(str(exc)) from exc
        _validate_logo_bytes(logo)
        result[key] = base64.b64encode(logo).decode("ascii")
    return result


def _theme_palette(value: Any) -> None:
    expected = {
        "backgroundHex",
        "primaryTextHex",
        "secondaryTextHex",
        "tertiaryTextHex",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise MarketplacePublishError("Selected theme palette is invalid")
    colors: list[str] = []
    for key in (
        "backgroundHex",
        "primaryTextHex",
        "secondaryTextHex",
        "tertiaryTextHex",
    ):
        color = value.get(key)
        if not isinstance(color, str) or not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
            raise MarketplacePublishError("Selected theme palette color is invalid")
        colors.append(color)
    for foreground in colors[1:]:
        if _contrast_ratio(colors[0], foreground) < 4.5:
            raise MarketplacePublishError("Selected theme text contrast is insufficient")


def _contrast_ratio(first: str, second: str) -> float:
    def luminance(value: str) -> float:
        channels = [int(value[offset : offset + 2], 16) / 255 for offset in (0, 2, 4)]
        converted = [
            channel / 12.92
            if channel <= 0.04045
            else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * converted[0] + 0.7152 * converted[1] + 0.0722 * converted[2]

    one, two = luminance(first), luminance(second)
    return (max(one, two) + 0.05) / (min(one, two) + 0.05)


def _validate_logo_bytes(value: bytes) -> None:
    width = height = 0
    if value.startswith(b"\x89PNG\r\n\x1a\n") and len(value) >= 24:
        width = int.from_bytes(value[16:20], "big")
        height = int.from_bytes(value[20:24], "big")
    elif value.startswith(b"\xff\xd8"):
        width, height = _jpeg_dimensions(value)
    else:
        raise MarketplacePublishError("Theme logo format is unsupported")
    if (
        width <= 0
        or height <= 0
        or width > 4_096
        or height > 4_096
        or width * height > 4_000_000
    ):
        raise MarketplacePublishError("Theme logo dimensions are invalid")


def _jpeg_dimensions(value: bytes) -> tuple[int, int]:
    offset = 2
    while offset + 9 < len(value):
        if value[offset] != 0xFF:
            offset += 1
            continue
        marker = value[offset + 1]
        offset += 2
        if marker in {0xD8, 0xD9}:
            continue
        if offset + 2 > len(value):
            break
        length = int.from_bytes(value[offset : offset + 2], "big")
        if length < 2 or offset + length > len(value):
            break
        if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
            if length < 7:
                break
            return (
                int.from_bytes(value[offset + 5 : offset + 7], "big"),
                int.from_bytes(value[offset + 3 : offset + 5], "big"),
            )
        offset += length
    raise MarketplacePublishError("Theme JPEG dimensions are invalid")


def _draft_id(value: Any) -> str:
    draft_id = value.get("id") if isinstance(value, dict) else None
    if not isinstance(draft_id, str) or not _RESOURCE_ID.fullmatch(draft_id):
        raise MarketplacePublishError("Marketplace draft response is invalid")
    return draft_id


def _draft_resource_id(value: Any) -> str:
    if not isinstance(value, str) or not _RESOURCE_ID.fullmatch(value):
        raise MarketplacePublishError("Marketplace draft ID is invalid")
    return value


def _draft_revision(value: Any, *, allow_zero: bool) -> int:
    revision = value.get("revision") if isinstance(value, dict) else None
    minimum = 0 if allow_zero else 1
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or not minimum <= revision <= 9_007_199_254_740_991
    ):
        raise MarketplacePublishError("Marketplace draft response is invalid")
    return revision


def _draft_readback(value: Any, *, expected_kind: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MarketplacePublishError("Marketplace draft readback is invalid")
    draft_id = _draft_id(value)
    revision = _draft_revision(value, allow_zero=False)
    if value.get("kind") != expected_kind:
        raise MarketplacePublishError("Marketplace draft readback kind is invalid")
    digest = value.get("sha256")
    validation_state = value.get("validationState")
    state = value.get("state")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise MarketplacePublishError("Marketplace draft readback digest is invalid")
    if validation_state not in {"pending", "valid", "blocked"}:
        raise MarketplacePublishError("Marketplace draft validation state is invalid")
    if state not in {
        "draft",
        "checking",
        "in_review",
        "published",
        "rejected",
        "withdrawn",
    }:
        raise MarketplacePublishError("Marketplace draft state is invalid")
    raw_findings = value.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) > 100:
        raise MarketplacePublishError("Marketplace draft findings are invalid")
    findings: list[dict[str, str]] = []
    for raw in raw_findings:
        if (
            not isinstance(raw, dict)
            or set(raw) not in (
                {"code", "severity", "message"},
                {"code", "severity", "message", "path"},
            )
            or raw.get("severity") not in {"warning", "blocking"}
        ):
            raise MarketplacePublishError("Marketplace draft findings are invalid")
        finding = {
            "code": _publication_text(raw.get("code"), "finding code", 1, 80, trim=True),
            "severity": raw["severity"],
            "message": _publication_text(
                raw.get("message"), "finding message", 1, 500, trim=True
            ),
        }
        if "path" in raw:
            finding["path"] = _publication_text(
                raw.get("path"), "finding path", 1, 512, trim=True
            )
        findings.append(finding)
    return {
        "draftId": draft_id,
        "revision": revision,
        "sha256": digest,
        "validationState": validation_state,
        "findings": findings,
        "state": state,
    }


def parse_skill_package(raw: bytes) -> MarketplaceSkillPackage:
    if not raw or len(raw) > _MAX_SKILL_PACKAGE_BYTES:
        raise MarketplaceInstallError("Skill package exceeds the 1.5 MB encoded limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, MarketplaceInstallError) as exc:
        if isinstance(exc, MarketplaceInstallError):
            raise
        raise MarketplaceInstallError("Skill package must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "kind", "content"}:
        raise MarketplaceInstallError("Skill package envelope is invalid")
    if value["schemaVersion"] != 1 or value["kind"] != "skill":
        raise MarketplaceInstallError("Skill package kind or schema is unsupported")
    content = value["content"]
    if not isinstance(content, dict) or set(content) != {"name", "skillMd", "files"}:
        raise MarketplaceInstallError("Skill package content is invalid")
    name = content["name"]
    skill_md = content["skillMd"]
    encoded_files = content["files"]
    if not isinstance(name, str) or not _SKILL_NAME.fullmatch(name):
        raise MarketplaceInstallError("Skill package name is invalid")
    if not isinstance(skill_md, str):
        raise MarketplaceInstallError("SKILL.md must be UTF-8 text")
    skill_bytes = skill_md.encode("utf-8")
    if not skill_bytes or len(skill_bytes) > _MAX_SKILL_FILE_BYTES:
        raise MarketplaceInstallError("SKILL.md exceeds the 100,000-byte limit")
    if not isinstance(encoded_files, dict) or len(encoded_files) + 1 > _MAX_SKILL_FILES:
        raise MarketplaceInstallError("Skill package has an invalid file count")

    files: dict[str, str] = {}
    seen = {unicodedata.normalize("NFKC", "SKILL.md").casefold()}
    total = len(skill_bytes)
    for path, encoded in encoded_files.items():
        normalized = _skill_path(path)
        collision_key = unicodedata.normalize("NFKC", normalized).casefold()
        if collision_key in seen:
            raise MarketplaceInstallError("Skill package contains colliding file paths")
        seen.add(collision_key)
        if not isinstance(encoded, str) or len(encoded) > 4 * ((_MAX_SKILL_FILE_BYTES + 2) // 3):
            raise MarketplaceInstallError("Skill package file encoding is invalid")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise MarketplaceInstallError("Skill package file encoding is invalid") from exc
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise MarketplaceInstallError("Skill package file encoding is not canonical base64")
        if len(decoded) > _MAX_SKILL_FILE_BYTES:
            raise MarketplaceInstallError("Skill package file exceeds 100,000 bytes")
        total += len(decoded)
        if total > _MAX_SKILL_DECODED_BYTES:
            raise MarketplaceInstallError("Skill package exceeds the 2 MB decoded limit")
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MarketplaceInstallError("Skill package files must be UTF-8 text") from exc
        if "\x00" in text:
            raise MarketplaceInstallError("Skill package contains binary content")
        files[normalized] = text

    from .workspace_control import WorkspaceControlError, _skill_content

    try:
        skill_md = _skill_content(skill_md, expected_name=name)
    except WorkspaceControlError as exc:
        raise MarketplaceInstallError(str(exc)) from exc
    return MarketplaceSkillPackage(name=name, skill_md=skill_md, files=files)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MarketplaceInstallError("Marketplace JSON contains a duplicate key")
        result[key] = value
    return result


def _skill_path(value: Any) -> str:
    if not isinstance(value, str) or not value or value != unicodedata.normalize("NFC", value):
        raise MarketplaceInstallError("Skill package contains an unsafe path")
    if value.startswith(("/", "\\")) or "\\" in value or any(ord(ch) < 32 for ch in value):
        raise MarketplaceInstallError("Skill package contains an unsafe path")
    path = PurePosixPath(value)
    if (
        len(path.parts) < 2
        or path.parts[0] not in _SAFE_ROOTS
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
        or not _SKILL_PATH.fullmatch(value)
    ):
        raise MarketplaceInstallError("Skill package contains an unsafe path")
    lowered = value.casefold()
    if lowered.endswith(_FORBIDDEN_SKILL_SUFFIXES):
        raise MarketplaceInstallError(
            "Nested archives and forbidden executable types are not allowed in skill packages"
        )
    return value


def _install_request(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "agentId",
        "itemId",
        "version",
        "sha256",
        "approvalId",
        "requestId",
    }:
        raise MarketplaceInstallError("Marketplace skill install request is invalid")
    result = _status_request(
        {"agentId": payload.get("agentId"), "itemId": payload.get("itemId")}
    )
    version = payload.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= 9_007_199_254_740_991:
        raise MarketplaceInstallError("Marketplace release version is invalid")
    digest = payload.get("sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise MarketplaceInstallError("Marketplace release digest is invalid")
    approval = payload.get("approvalId")
    request = payload.get("requestId")
    if not isinstance(approval, str) or not _RESOURCE_ID.fullmatch(approval):
        raise MarketplaceInstallError("Marketplace install approval is invalid")
    if not isinstance(request, str) or not _RESOURCE_ID.fullmatch(request):
        raise MarketplaceInstallError("Marketplace install request ID is invalid")
    return {
        **result,
        "version": version,
        "sha256": digest,
        "approvalId": approval,
        "requestId": request,
    }


def _status_request(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != {"agentId", "itemId"}:
        raise MarketplaceInstallError("Marketplace skill status request is invalid")
    agent = payload.get("agentId")
    item = payload.get("itemId")
    if not isinstance(agent, str) or not _AGENT_ID.fullmatch(agent):
        raise MarketplaceInstallError("Marketplace target agent is invalid")
    if not isinstance(item, str) or not _RESOURCE_ID.fullmatch(item):
        raise MarketplaceInstallError("Marketplace item ID is invalid")
    return {"agentId": agent, "itemId": item}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _require_success(response: MarketplaceHTTPResponse, *, label: str) -> None:
    if response.status < 200 or response.status >= 300:
        raise MarketplaceInstallError(
            f"Marketplace {label} failed with status {response.status}"
        )


def _require_json_content_type(response: MarketplaceHTTPResponse) -> None:
    headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise MarketplaceInstallError("Marketplace returned an invalid content type")


def _successful_json_response(
    response: MarketplaceHTTPResponse, *, label: str
) -> dict[str, Any]:
    _require_success(response, label=label)
    _require_json_content_type(response)
    try:
        value = json.loads(response.body.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MarketplaceInstallError(f"Marketplace {label} response is invalid") from exc
    if not isinstance(value, dict):
        raise MarketplaceInstallError(f"Marketplace {label} response is invalid")
    return value


def _decoded_standard_base64(value: Any, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 4 * ((maximum + 2) // 3):
        raise MarketplaceInstallError(f"Marketplace {label} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise MarketplaceInstallError(f"Marketplace {label} is invalid") from exc
    if len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise MarketplaceInstallError(f"Marketplace {label} is invalid")
    return decoded


def _ed25519_public_key(value: Any) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if isinstance(value, ed25519.Ed25519PublicKey):
        return value
    if isinstance(value, bytes) and len(value) == 32:
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(value)
        except ValueError as exc:
            raise MarketplaceInstallError("Marketplace trust key is invalid") from exc
    raise MarketplaceInstallError("Marketplace trust key is invalid")


def _verified_skill_manifest(
    *,
    envelope: Mapping[str, Any],
    trust_keys: Mapping[str, Any],
    item_id: str,
    version: int,
    sha256: str,
) -> tuple[dict[str, Any], str]:
    if set(envelope) != {"keyId", "manifestBase64", "signatureBase64"}:
        raise MarketplaceInstallError("Marketplace release envelope is invalid")
    key_id = envelope.get("keyId")
    if not isinstance(key_id, str) or key_id not in trust_keys:
        raise MarketplaceInstallError("Marketplace release signing key is not trusted")
    manifest_bytes = _decoded_standard_base64(
        envelope.get("manifestBase64"), label="manifest bytes", maximum=96 * 1024
    )
    signature = _decoded_standard_base64(
        envelope.get("signatureBase64"), label="manifest signature", maximum=64
    )
    if len(signature) != 64:
        raise MarketplaceInstallError("Marketplace manifest signature is invalid")
    try:
        trust_keys[key_id].verify(signature, manifest_bytes)
    except Exception as exc:
        raise MarketplaceInstallError("Marketplace manifest signature is invalid") from exc
    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MarketplaceInstallError("Marketplace signed manifest is invalid") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schemaVersion",
        "item",
        "artifactPath",
    }:
        raise MarketplaceInstallError("Marketplace signed manifest is invalid")
    if manifest.get("schemaVersion") != 1:
        raise MarketplaceInstallError("Marketplace signed manifest schema is unsupported")
    listing = _skill_listing(manifest.get("item"))
    expected_path = f"/v1/marketplace/items/{item_id}/versions/{version}/artifact"
    if (
        listing["id"] != item_id
        or listing["version"] != version
        or not hmac.compare_digest(listing["sha256"], sha256)
        or manifest.get("artifactPath") != expected_path
    ):
        raise MarketplaceInstallError("Marketplace signed manifest does not match approval")
    return listing, expected_path


def _skill_listing(value: Any) -> dict[str, Any]:
    expected = {
        "id",
        "kind",
        "name",
        "summary",
        "description",
        "author",
        "publisherId",
        "license",
        "version",
        "sha256",
        "byteCount",
        "minimumAppVersion",
        "requiredCapabilities",
        "tags",
        "publishedAt",
        "preview",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("kind") != "skill":
        raise MarketplaceInstallError("Marketplace skill listing is invalid")
    item = value.get("id")
    publisher = value.get("publisherId")
    if (
        not isinstance(item, str)
        or not _RESOURCE_ID.fullmatch(item)
        or not isinstance(publisher, str)
        or not _RESOURCE_ID.fullmatch(publisher)
    ):
        raise MarketplaceInstallError("Marketplace skill listing is invalid")
    version = value.get("version")
    byte_count = value.get("byteCount")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version < 1
        or isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or not 0 < byte_count <= _MAX_SKILL_PACKAGE_BYTES
    ):
        raise MarketplaceInstallError("Marketplace skill listing is invalid")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise MarketplaceInstallError("Marketplace skill listing is invalid")
    text_bounds = {
        "name": (1, 80),
        "summary": (1, 240),
        "description": (0, 8_000),
        "author": (1, 80),
        "license": (1, 64),
        "minimumAppVersion": (5, 32),
        "publishedAt": (1, 64),
    }
    for key, (minimum, maximum) in text_bounds.items():
        field = value.get(key)
        if (
            not isinstance(field, str)
            or not minimum <= len(field) <= maximum
            or any(ord(character) < 32 for character in field)
        ):
            raise MarketplaceInstallError("Marketplace skill listing is invalid")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["minimumAppVersion"]):
        raise MarketplaceInstallError("Marketplace skill listing is invalid")
    for key, limit, width in (
        ("tags", 8, 24),
        ("requiredCapabilities", 16, 64),
    ):
        entries = value.get(key)
        if (
            not isinstance(entries, list)
            or len(entries) > limit
            or len(entries) != len(set(entries))
            or any(
                not isinstance(entry, str)
                or not 1 <= len(entry) <= width
                or any(ord(character) < 32 or ord(character) > 126 for character in entry)
                for entry in entries
            )
        ):
            raise MarketplaceInstallError("Marketplace skill listing is invalid")
    preview = value.get("preview")
    if not isinstance(preview, dict) or len(_canonical_json_bytes(preview)) > 16 * 1024:
        raise MarketplaceInstallError("Marketplace skill listing is invalid")
    return dict(value)


__all__ = [
    "CARD_TEMPLATE_CAPABILITY",
    "HermesHubCLI",
    "MARKETPLACE_SKILL_CAPABILITY",
    "MarketplaceGatewayClient",
    "MarketplaceHTTPTransport",
    "MarketplaceHTTPResponse",
    "MarketplaceInstallError",
    "MarketplacePublishError",
    "MarketplacePublisher",
    "MarketplaceSkillInstaller",
    "MarketplaceSkillPackage",
    "parse_skill_package",
    "build_marketplace_gateway_client",
    "load_marketplace_trust_keys",
]
