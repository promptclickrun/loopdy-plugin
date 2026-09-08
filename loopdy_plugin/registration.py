"""Hermes registration and CLI surfaces for Loopdy."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home

from .adapter import (
    LoopdyAdapter,
    check_requirements,
    env_enablement,
    get_service,
    is_connected,
    profile_display_name,
    release_service,
    standalone_send,
    validate_config,
)
from .approval import LoopdyApprovalTransport
from .activity_bridge import (
    LinkActivityBroker,
    external_turn_id,
    finish_failed_turn_activity,
    publish_hook_activity,
)
from .attachments import AttachmentStore
from .hooks import normalize_hook
from .generative_ui import parse_v2_json, validate_rendered_envelope
from .link_client import load_runtime_config
from .link_contracts import generative_ui_event
from .link_identity import pre_llm_context_from_state
from .link_pairing import LINK_ENV_KEYS, pair_host
from .marketplace import MarketplaceGatewayClient, MarketplacePublisher
from .plugin_update import (
    PluginUpdateManager,
    local_cli_device_id,
    new_operation_id,
    production_manager,
)
from .providers.apns import load_apns_config
from .relay_client import RelayConfig
from .targets import parse_target, validate_target
from .tools import register as register_tools


NOTIFICATION_HOOKS = (
    "pre_tool_call",
    "on_session_end",
    "subagent_start",
    "subagent_stop",
    "kanban_task_claimed",
    "kanban_task_completed",
    "kanban_task_blocked",
)
DIRECT_OBSERVER_HOOKS = ("post_api_request", "on_session_reset")
HOOKS = (
    "pre_llm_call",
    "post_llm_call",
    "post_tool_call",
    *DIRECT_OBSERVER_HOOKS,
    *NOTIFICATION_HOOKS,
)
logger = logging.getLogger("hermes.plugins.loopdy")


def register_marketplace_publish_skill(ctx: Any) -> None:
    """Register Loopdy's read-only publishing guidance with Hermes."""

    description = (
        "Use when publishing Loopdy themes, cards, or skills. "
        "Prepare a private draft for review in Loopdy."
    )
    ctx.register_skill(
        "loopdy-marketplace-publish",
        Path(__file__).resolve().parents[1]
        / "skills"
        / "loopdy-marketplace-publish"
        / "SKILL.md",
        description=description,
        frontmatter={
            "name": "loopdy-marketplace-publish",
            "description": description,
        },
    )


def register(
    ctx: Any,
    *,
    service: Any | None = None,
    activity_broker: LinkActivityBroker | Any | None = None,
    marketplace_gateway_client: Any | None = None,
    attachment_store: AttachmentStore | Any | None = None,
) -> None:
    active_service = service or get_service()
    broker = activity_broker or LinkActivityBroker()
    attach_duration_store = getattr(broker, "attach_duration_store", None)
    if callable(attach_duration_store):
        attach_duration_store(getattr(active_service, "store", None))
    profile = str(getattr(ctx, "profile_name", "default") or "default")
    identity_state = getattr(ctx, "state", None)
    update_manager = production_manager(profile)

    selected_attachment_store = attachment_store or AttachmentStore(
        get_hermes_home()
        / "plugin-data"
        / "loopdy"
        / "agent-attachments.sqlite3"
    )
    selected_gateway_client = marketplace_gateway_client
    if selected_gateway_client is None:
        try:
            runtime_config = load_runtime_config()
        except (TypeError, ValueError):
            runtime_config = None
        if runtime_config is not None:
            # Draft creation needs the paired host's signed-device identity;
            # release trust anchors are independently required for installs.
            selected_gateway_client = MarketplaceGatewayClient(
                config=runtime_config,
                trust_keys={},
            )
    register_tools(
        ctx,
        store=active_service.store,
        profile=profile,
        marketplace_publisher=MarketplacePublisher(
            agent_id=profile,
            store=active_service.store,
            attachment_store=selected_attachment_store,
            gateway_client=selected_gateway_client,
        ),
    )
    register_marketplace_publish_skill(ctx)

    ctx.register_platform(
        name="loopdy",
        label="Loopdy",
        adapter_factory=lambda config: LoopdyAdapter(
            config,
            service=active_service,
            link_state=identity_state,
            activity_broker=broker,
            plugin_update_manager=update_manager,
        ),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=[],
        install_hint=(
            "Run `hermes loopdy link pair` and approve the code in Loopdy."
        ),
        env_enablement_fn=env_enablement,
        cron_deliver_env_var="LOOPDY_HOME_TARGET",
        standalone_sender_fn=partial(
            standalone_send,
            service=active_service,
            link_state=identity_state,
        ),
        parse_target_ref_fn=parse_target,
        validate_target_ref_fn=validate_target,
        # Match the native assistant-text bound, leaving complete 64 KiB card
        # envelopes intact. The adapter splits ordinary Inbox text more tightly.
        max_message_length=100_000,
        emoji="L",
        pii_safe=True,
        allow_update_command=False,
    )

    approval = LoopdyApprovalTransport(
        active_service.store,
        active_service,
        target=_home_target(),
        profile=profile,
        agent_name=profile_display_name(profile),
    )
    ctx.register_approval_transport("loopdy", approval.present)

    ctx.register_hook(
        "pre_llm_call",
        partial(
            _pre_llm_call,
            service=active_service,
            profile=profile,
            identity_state=identity_state,
            activity_broker=broker,
        ),
    )
    ctx.register_hook(
        "post_llm_call",
        partial(
            _post_llm_call,
            service=active_service,
            profile=profile,
            activity_broker=broker,
        ),
    )
    ctx.register_hook(
        "post_tool_call",
        partial(_post_tool_call, service=active_service, activity_broker=broker),
    )
    record_api_usage = getattr(broker, "record_api_usage", None)
    if callable(record_api_usage):
        ctx.register_hook("post_api_request", record_api_usage)
    reset_api_usage = getattr(broker, "reset_api_usage", None)
    if callable(reset_api_usage):
        ctx.register_hook("on_session_reset", reset_api_usage)
    for hook_name in NOTIFICATION_HOOKS:
        ctx.register_hook(
            hook_name,
            partial(
                _deliver_hook,
                hook_name,
                service=active_service,
                profile=profile,
                activity_broker=broker,
            ),
        )

    ctx.register_cli_command(
        name="loopdy",
        help="Configure and inspect the Loopdy native channel",
        description="Manage the Loopdy mobile notification integration.",
        setup_fn=setup_cli,
        handler_fn=partial(
            handle_cli,
            service=active_service,
            profile=profile,
            identity_state=identity_state,
            plugin_update_manager=update_manager,
        ),
    )
    ctx.on_unload(partial(release_service, active_service))


def _pre_llm_call(
    *,
    service: Any,
    profile: str,
    identity_state: Any | None = None,
    activity_broker: LinkActivityBroker | Any,
    **payload: Any,
):
    publish_hook_activity(
        "pre_llm_call",
        broker=activity_broker,
        profile=profile,
        payload=payload,
    )
    _queue_live_activity_update(
        service,
        session_id=str(payload.get("session_id") or ""),
        profile=str(payload.get("profile_name") or profile),
        phase="thinking",
    )
    if str(payload.get("platform") or "").strip().lower() != "loopdy":
        return None
    sections: list[str] = []
    if identity_state is not None:
        identity = pre_llm_context_from_state(
            identity_state,
            platform="loopdy",
            sender_id=str(payload.get("sender_id") or ""),
        )
        if isinstance(identity, dict) and isinstance(identity.get("context"), str):
            sections.append(identity["context"])
    sections.append(
        "[Loopdy native presentation]\n"
        "When structured presentation is clearer than prose, call exactly one matching "
        "direct renderer such as loopdy_render_weather_forecast, "
        "loopdy_render_stock_quote, loopdy_render_chart, loopdy_render_dashboard, or "
        "loopdy_render_form. Those typed v2 renderers remain preferred for their existing "
        "polished use cases. For a new static layout that does not match a typed renderer, "
        "use loopdy_render_card with embedded values and an empty data_sources array. "
        "Live Loopdy Card data refresh is unavailable in this release. "
        "For current weather or forecast requests, use "
        "loopdy_render_weather_forecast after obtaining the data when a card is useful; "
        "if Hermes has progressively disclosed the renderer, use the official "
        "tool_search, tool_describe, and tool_call bridge to load and invoke that exact "
        "renderer. Do not stop at prose when the native card is relevant, and do not "
        "invent a replacement renderer."
    )
    return {"context": "\n\n".join(sections)}


def _post_llm_call(
    *,
    service: Any,
    profile: str,
    activity_broker: LinkActivityBroker | Any,
    **payload: Any,
) -> None:
    publish_hook_activity(
        "post_llm_call",
        broker=activity_broker,
        profile=profile,
        payload=payload,
    )
    service.store.dismiss_attention_for_session(
        str(payload.get("session_id") or payload.get("task_id") or "")
    )
    _queue_live_activity_update(
        service,
        session_id=str(payload.get("session_id") or payload.get("task_id") or ""),
        profile=str(payload.get("profile_name") or profile),
        phase="completed",
        active_session_count=0,
    )


def _post_tool_call(
    *,
    service: Any,
    activity_broker: LinkActivityBroker | Any,
    **payload: Any,
) -> None:
    publish_hook_activity(
        "post_tool_call",
        broker=activity_broker,
        profile=str(payload.get("profile_name") or "default"),
        payload=payload,
    )
    _publish_generative_ui_result(activity_broker, payload)
    if str(payload.get("tool_name") or "").strip() != "clarify":
        return
    service.store.dismiss_attention_for_session(
        str(payload.get("session_id") or payload.get("task_id") or "")
    )


def _publish_generative_ui_result(
    broker: LinkActivityBroker | Any,
    payload: dict[str, Any],
) -> None:
    tool_name = str(payload.get("tool_name") or "").strip()
    if not tool_name.startswith("loopdy_render_"):
        return
    if str(payload.get("status") or "").strip().lower() not in {
        "ok", "success", "succeeded", "completed",
    }:
        return
    session_id = str(payload.get("session_id") or "").strip()
    turn_id = str(payload.get("turn_id") or "").strip()
    tool_call_id = str(payload.get("tool_call_id") or "").strip()
    link_session_id = (
        broker.resolved_session_id(session_id, turn_id)
        if session_id and turn_id
        else None
    )
    if not link_session_id or not tool_call_id:
        return
    try:
        result = payload.get("result")
        decoded = result if isinstance(result, dict) else parse_v2_json(result)
        card = validate_rendered_envelope(decoded)
        profile = str(payload.get("profile_name") or "default").strip() or "default"
        digest = hashlib.sha256(
            f"{link_session_id}\x1f{turn_id}\x1f{tool_call_id}".encode("utf-8")
        ).hexdigest()[:32]
        event = generative_ui_event(
            event_id=f"card_{digest}",
            session_id=link_session_id,
            turn_id=external_turn_id(link_session_id, turn_id),
            tool_call_id=tool_call_id,
            agent_id=str(payload.get("agent_id") or profile),
            agent_name=profile_display_name(profile),
            card=card,
            occurred_at=int(time.time()),
        )
    except (TypeError, ValueError):
        logger.warning("Hermes renderer result was invalid")
        return
    if not broker.publish(event):
        logger.debug("Loopdy Link generative UI has no attached socket")


def _deliver_hook(
    hook_name: str,
    *,
    service: Any,
    profile: str,
    activity_broker: LinkActivityBroker | Any,
    **payload: Any,
) -> None:
    if hook_name == "on_session_end":
        service.store.dismiss_attention_for_session(
            str(payload.get("session_id") or payload.get("task_id") or "")
        )
    event = normalize_hook(hook_name, profile=profile, **payload)
    if event is not None:
        if not event.detail.get("agent_name"):
            event = replace(
                event,
                detail={
                    **event.detail,
                    "agent_name": profile_display_name(event.profile),
                },
            )
        service.enqueue(event, target=_home_target())
    _live_activity_from_hook(hook_name, service=service, profile=profile, payload=payload)
    if hook_name == "on_session_end":
        finish_failed_turn_activity(broker=activity_broker, payload=payload)
    else:
        publish_hook_activity(
            hook_name,
            broker=activity_broker,
            profile=profile,
            payload=payload,
        )


def _live_activity_from_hook(
    hook_name: str, *, service: Any, profile: str, payload: dict[str, Any]
) -> None:
    session_id = str(payload.get("session_id") or payload.get("task_id") or "").strip()
    if not session_id:
        return
    selected_profile = str(payload.get("profile_name") or profile or "default")
    phase = ""
    if hook_name == "pre_tool_call":
        tool_name = str(payload.get("tool_name") or "tool")[:80]
        if tool_name == "clarify":
            phase = "waiting"
        else:
            phase = "running"
    elif hook_name == "on_session_end":
        failed = bool(payload.get("failed") or payload.get("interrupted"))
        if not failed:
            return
        phase = "failed"
    if phase:
        _queue_live_activity_update(
            service,
            session_id=session_id,
            profile=selected_profile,
            phase=phase,
            active_session_count=0 if phase in {"completed", "failed"} else 1,
        )


def _queue_live_activity_update(service: Any, **update: Any) -> None:
    if not str(update.get("session_id") or "").strip():
        return
    if not service.enqueue_live_activity_update(**update):
        logger.warning("Loopdy Live Activity update was not queued")


def setup_cli(parser: Any) -> None:
    actions = parser.add_subparsers(dest="loopdy_action", required=True)
    from .wiki_cli import setup_wiki_cli
    setup_wiki_cli(actions)

    actions.add_parser("status", help="Show provider health and registered devices")

    files = actions.add_parser(
        "files",
        help="Manage explicit read-only workspace file grants",
    )
    file_actions = files.add_subparsers(dest="loopdy_files_action", required=True)
    grant = file_actions.add_parser("grant", help="Grant one host-local workspace root")
    grant.add_argument("workspace_id")
    grant.add_argument("--root", required=True)
    grant.add_argument("--label", required=True)
    revoke = file_actions.add_parser("revoke", help="Revoke one workspace root")
    revoke.add_argument("workspace_id")
    revoke.add_argument("--yes", action="store_true", help="Confirm revocation")
    file_actions.add_parser("roots", help="List granted workspace labels")
    list_files = file_actions.add_parser("list", help="List a granted directory")
    list_files.add_argument("workspace_id")
    list_files.add_argument("--path", default="")
    list_files.add_argument("--offset", type=int, default=0)
    list_files.add_argument("--limit", type=int, default=100)
    list_files.add_argument("--query", default="")
    list_files.add_argument("--revision")
    read = file_actions.add_parser("read", help="Read one bounded file chunk")
    read.add_argument("workspace_id")
    read.add_argument("path")
    read.add_argument("--offset", type=int, default=0)
    read.add_argument("--limit", type=int, default=65_536)
    read.add_argument("--revision")
    file_status = file_actions.add_parser("status", help="Show read-only Git status")
    file_status.add_argument("workspace_id")
    diff = file_actions.add_parser("diff", help="Show a bounded read-only Git diff")
    diff.add_argument("workspace_id")
    diff.add_argument("path")
    diff.add_argument("--side", choices=("staged", "worktree"), required=True)
    diff.add_argument("--expected-status-token", required=True)
    diff.add_argument("--offset", type=int, default=0)
    diff.add_argument("--limit", type=int, default=300)

    update = actions.add_parser(
        "update",
        help="Install the latest immutable Loopdy plugin revision",
    )
    update.add_argument(
        "--restart",
        action="store_true",
        help="Explicitly authorize one gateway restart after installation",
    )
    actions.add_parser(
        "update-status",
        help="Read the latest durable plugin update status",
    )

    provider = actions.add_parser("provider", help="Show or select the push provider")
    provider.add_argument("mode", nargs="?", choices=("managed", "direct", "relay"))

    configure_apns = actions.add_parser(
        "configure-apns",
        help="Configure host-only credentials for direct APNs delivery",
    )
    configure_apns.add_argument("--team-id", required=True)
    configure_apns.add_argument("--key-id", required=True)
    configure_apns.add_argument("--topic", required=True)
    configure_apns.add_argument(
        "--environment",
        choices=("production", "sandbox"),
        default="production",
    )
    configure_apns.add_argument("--key-path", required=True)

    remove_apns = actions.add_parser(
        "remove-apns",
        help="Remove direct APNs configuration from this Hermes host",
    )
    remove_apns.add_argument("--yes", action="store_true", help="Confirm removal")

    configure_relay = actions.add_parser(
        "configure-relay",
        help="Configure relay coordinates and local secret references",
    )
    configure_relay.add_argument("--base-url", required=True)
    configure_relay.add_argument("--tenant-id", required=True)
    configure_relay.add_argument("--credential-key-id", required=True)
    configure_relay.add_argument("--hmac-secret-ref", required=True)
    configure_relay.add_argument("--signing-key-secret-ref", required=True)

    remove_relay = actions.add_parser(
        "remove-relay",
        help="Remove relay configuration from this Hermes host",
    )
    remove_relay.add_argument("--yes", action="store_true", help="Confirm removal")

    recover_relay_registration = actions.add_parser(
        "recover-terminal-relay-registration",
        help="Apply verified stored relay registrations without network calls",
    )
    recover_relay_registration.add_argument(
        "--yes",
        action="store_true",
        help="Confirm local journal recovery",
    )

    test = actions.add_parser("test", help="Send an opaque test wakeup")
    test.add_argument("--target", default=_home_target())

    link = actions.add_parser("link", help="Pair and inspect Loopdy Link")
    link_actions = link.add_subparsers(dest="loopdy_link_action", required=True)
    pair = link_actions.add_parser("pair", help="Pair this Hermes host")
    pair.add_argument("--base-url", default="https://link.loopdy.app")
    pair.add_argument("--timeout", type=int, default=600)
    link_actions.add_parser("status", help="Show redacted Loopdy Link status")
    unpair = link_actions.add_parser("unpair", help="Remove this host pairing")
    unpair.add_argument("--yes", action="store_true", help="Confirm removal")


def handle_cli(
    args: Any,
    *,
    service: Any,
    profile: str,
    identity_state: Any | None = None,
    plugin_update_manager: PluginUpdateManager | None = None,
) -> None:
    action = str(getattr(args, "loopdy_action", "") or "")
    if action == "wiki":
        from .wiki_cli import handle_wiki_cli
        from .wiki_transport import production_factory
        handle_wiki_cli(args, transport=production_factory(
            host_home=get_hermes_home(), config_getter=load_runtime_config,
        ))
        return
    if action == "files":
        _handle_files_cli(args)
        return
    if action == "link":
        _handle_link_cli(args, identity_state=identity_state)
        return
    if action in {"update", "update-status"}:
        manager = plugin_update_manager or production_manager(profile)
        if action == "update-status":
            _print_json(manager.status())
            return
        current = manager.status()
        if current["phase"] not in {
            "idle",
            "complete",
            "up_to_date",
            "installed_restart_required",
            "blocked",
            "failed",
        }:
            _print_json(current)
            return
        _print_json(
            manager.start(
                operation_id=new_operation_id(),
                device_id=local_cli_device_id(profile),
                restart=bool(getattr(args, "restart", False)),
            )
        )
        return
    if action == "status":
        apns = service.store.load_apns_config()
        _print_json(
            {
                "devices": [
                    _public_device(value) for value in service.store.list_devices()
                ],
                "home_target": _home_target(),
                "provider": service.store.provider_mode(),
                "provider_health": service.health(),
                "apns": _redacted_apns_config(apns),
                "relay": _redacted_relay_config(
                    getattr(service.store, "load_relay_config", lambda: None)()
                ),
            }
        )
        return
    if action == "provider":
        requested_mode = getattr(args, "mode", None)
        if requested_mode:
            service.set_provider_mode(requested_mode)
        _print_json(
            {
                "provider": service.store.provider_mode(),
                "provider_health": service.health(),
            }
        )
        return
    if action == "configure-apns":
        config = load_apns_config(
            {
                "team_id": args.team_id,
                "key_id": args.key_id,
                "topic": args.topic,
                "environment": args.environment,
                "key_path": args.key_path,
            },
            os.environ,
        )
        service.store.save_apns_config(config.stored_values())
        service.set_provider_mode("direct")
        _print_json(
            {
                "provider": "direct",
                "apns": _redacted_apns_config(config.stored_values()),
            }
        )
        return
    if action == "remove-apns":
        if not bool(getattr(args, "yes", False)):
            raise ValueError("Pass --yes to confirm APNs configuration removal")
        service.store.clear_apns_config()
        if service.store.provider_mode() == "direct":
            service.set_provider_mode("managed")
        _print_json({"provider": service.store.provider_mode(), "apns": None})
        return
    if action == "configure-relay":
        config = RelayConfig(
            base_url=args.base_url,
            tenant_id=args.tenant_id,
            credential_key_id=args.credential_key_id,
            hmac_secret_reference=args.hmac_secret_ref,
            signing_key_secret_reference=args.signing_key_secret_ref,
        )
        service.configure_relay(config)
        _print_json(
            {
                "provider": "relay",
                "relay": _redacted_relay_config(config.stored_values()),
            }
        )
        return
    if action == "remove-relay":
        if not bool(getattr(args, "yes", False)):
            raise ValueError("Pass --yes to confirm relay configuration removal")
        service.remove_relay_configuration()
        _print_json({"provider": service.store.provider_mode(), "relay": None})
        return
    if action == "recover-terminal-relay-registration":
        if not bool(getattr(args, "yes", False)):
            raise ValueError("Pass --yes to confirm stored relay registration recovery")
        _print_json(service.recover_terminal_relay_registrations())
        return
    if action == "test":
        target = str(args.target or "all").strip()
        verdict = validate_target(target)
        if verdict is not True:
            raise ValueError(str(verdict))
        _print_json(service.test_notification(target=target, profile=profile))
        return
    raise ValueError("Unknown Loopdy command")


def _handle_files_cli(args: Any) -> None:
    from hermes_constants import get_hermes_home

    from .workspace_files import WorkspaceFilesError, WorkspaceFilesService

    action = str(getattr(args, "loopdy_files_action", "") or "")
    try:
        service = WorkspaceFilesService(
            get_hermes_home() / "plugin-data" / "loopdy" / "workspace-files"
        )
        if action == "grant":
            result = service.grant(
                str(args.workspace_id),
                root=Path(str(args.root)),
                label=str(args.label),
            )
        elif action == "revoke":
            if not bool(getattr(args, "yes", False)):
                raise WorkspaceFilesError(
                    "INVALID_REQUEST", "Pass --yes to confirm workspace revocation"
                )
            result = service.revoke(str(args.workspace_id))
        elif action == "roots":
            result = service.roots()
        elif action == "list":
            result = service.list_directory(
                str(args.workspace_id),
                path=str(args.path),
                offset=int(args.offset),
                limit=int(args.limit),
                query=str(args.query),
                revision=getattr(args, "revision", None),
            )
        elif action == "read":
            result = service.read_file(
                str(args.workspace_id),
                path=str(args.path),
                offset=int(args.offset),
                limit=int(args.limit),
                revision=getattr(args, "revision", None),
            )
        elif action == "status":
            result = service.git_status(str(args.workspace_id))
        elif action == "diff":
            result = service.git_diff(
                str(args.workspace_id),
                path=str(args.path),
                side=str(args.side),
                expected_status_token=str(args.expected_status_token),
                offset=int(args.offset),
                limit=int(args.limit),
            )
        else:
            raise WorkspaceFilesError(
                "INVALID_REQUEST", "Unknown Loopdy Files command"
            )
    except WorkspaceFilesError as error:
        _print_json(error.envelope())
        raise SystemExit(1) from None
    except Exception:
        _print_json(
            WorkspaceFilesError(
                "FILES_UNAVAILABLE", "Workspace Files request failed"
            ).envelope()
        )
        raise SystemExit(1) from None
    _print_json(result)


def _handle_link_cli(args: Any, *, identity_state: Any | None = None) -> None:
    from hermes_cli.config import remove_env_value, save_env_value

    action = str(getattr(args, "loopdy_link_action", "") or "")
    if action == "pair":
        timeout = int(getattr(args, "timeout", 600) or 600)
        if timeout < 30 or timeout > 600:
            raise ValueError("Loopdy Link pairing timeout must be 30-600 seconds")
        result = pair_host(
            str(args.base_url),
            save_secret=save_env_value,
            announce=_print_json,
            timeout_seconds=timeout,
        )
        if identity_state is not None:
            identity_state.set("link.runtime_status", None)
        activation_requested = _request_gateway_activation()
        _print_json(
            {
                **result,
                "gateway_activation": (
                    "requested" if activation_requested else "unavailable"
                ),
            }
        )
        return
    if action == "status":
        try:
            config = load_runtime_config()
            value = _link_status_value(config, identity_state)
        except ValueError as exc:
            value = {
                "configured": False,
                "state": "configuration_invalid",
                "detail": str(exc),
            }
        _print_json(value)
        return
    if action == "unpair":
        if not bool(getattr(args, "yes", False)):
            raise ValueError("Pass --yes to confirm Loopdy Link unpairing")
        removed = 0
        for key in LINK_ENV_KEYS:
            removed += int(bool(remove_env_value(key)))
        if identity_state is not None:
            identity_state.set("link.runtime_status", None)
        _print_json({"configured": False, "state": "unpaired", "removed": removed})
        return
    raise ValueError("Unknown Loopdy Link command")


def _request_gateway_activation() -> bool:
    """Ask the official Hermes lifecycle command to load the new pairing."""
    command = [sys.executable, "-m", "hermes_cli.main", "gateway", "restart"]
    options: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        options["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    else:
        options["start_new_session"] = True
    try:
        subprocess.Popen(command, **options)
        return True
    except OSError as exc:
        logger.warning("Loopdy Link could not request gateway activation: %s", exc)
        return False


def _link_status_value(config: Any | None, identity_state: Any | None) -> dict[str, Any]:
    if config is None:
        return {"configured": False, "state": "unpaired"}
    value: dict[str, Any] = {
        "configured": True,
        "state": "restart_required_or_connecting",
        "base_url": config.base_url,
        "device_id": config.device_id,
        "authorization_epoch": config.authorization_epoch,
    }
    if identity_state is None:
        return value
    runtime = identity_state.get("link.runtime_status")
    if not isinstance(runtime, dict):
        return value
    if (
        runtime.get("base_url") != config.base_url
        or runtime.get("device_id") != config.device_id
        or runtime.get("authorization_epoch") != config.authorization_epoch
    ):
        return value
    state = runtime.get("state")
    if state not in {
        "connected",
        "connecting",
        "reconnecting",
        "disconnected",
        "superseded",
        "unready",
        "configuration_error",
    }:
        return value
    value["state"] = state
    for key in ("observed_at", "last_connected_at", "reconnect_attempt"):
        if isinstance(runtime.get(key), int):
            value[key] = runtime[key]
    detail = str(runtime.get("detail") or "").strip()
    if detail:
        value["detail"] = detail[:160]
    return value


def _home_target() -> str:
    target = os.getenv("LOOPDY_HOME_TARGET", "all").strip() or "all"
    return target if validate_target(target) is True else "all"


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _redacted_apns_config(config: Any) -> dict[str, Any] | None:
    if not isinstance(config, dict):
        return None
    return {
        "team_id": str(config.get("team_id") or ""),
        "key_id": str(config.get("key_id") or ""),
        "topic": str(config.get("topic") or ""),
        "environment": str(config.get("environment") or ""),
        "key_file": os.path.basename(str(config.get("key_path") or "")),
    }


def _redacted_relay_config(config: Any) -> dict[str, Any] | None:
    if not isinstance(config, dict):
        return None
    return {
        "base_url": str(config.get("base_url") or ""),
        "tenant_id": str(config.get("tenant_id") or ""),
        "credential_key_id": str(config.get("credential_key_id") or ""),
        "hmac_secret_reference_configured": bool(config.get("hmac_secret_reference")),
        "signing_key_secret_reference_configured": bool(
            config.get("signing_key_secret_reference")
        ),
    }


def _public_device(device: Any) -> dict[str, Any]:
    value = dict(device) if isinstance(device, dict) else {}
    endpoint = str(value.pop("endpoint_id", "") or "")
    value.pop("recipient_public_key", None)
    value["token_fingerprint"] = (
        hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:12] if endpoint else ""
    )
    return value
