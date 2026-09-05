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
from typing import Any

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
from .hooks import normalize_hook
from .generative_ui import parse_v2_json, validate_rendered_envelope
from .link_client import load_runtime_config
from .link_contracts import generative_ui_event
from .link_identity import pre_llm_context_from_state
from .link_pairing import LINK_ENV_KEYS, pair_host
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
HOOKS = ("pre_llm_call", "post_llm_call", "post_tool_call", *NOTIFICATION_HOOKS)
logger = logging.getLogger("hermes.plugins.loopdy")


def register(
    ctx: Any,
    *,
    service: Any | None = None,
    activity_broker: LinkActivityBroker | Any | None = None,
) -> None:
    active_service = service or get_service()
    broker = activity_broker or LinkActivityBroker()
    profile = str(getattr(ctx, "profile_name", "default") or "default")
    identity_state = getattr(ctx, "state", None)
    update_manager = production_manager(profile)

    # Renderer tools are registered directly. Avoid registering a companion skill
    # here because plugin skills are advertised through the model's system prompt.
    register_tools(ctx, store=active_service.store, profile=profile)

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
        max_message_length=4096,
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


def _card_template_agent_id(value: Any) -> str:
    agent_id = str(value or "").strip()
    if (
        not agent_id
        or len(agent_id) > 64
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in agent_id)
        or not agent_id[0].isalnum()
    ):
        raise ValueError("Card template agent ownership is invalid")
    return agent_id


def _card_template_projection(template: dict[str, Any]) -> dict[str, Any]:
    return {
        key: template[key]
        for key in (
            "id", "version", "name", "summary", "author", "license",
            "minimum_card_version", "sha256",
        )
    }


async def _cards_templates_list(backend: Any, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"agentId"}:
        raise ValueError("Card template list payload is invalid")
    agent_id = _card_template_agent_id(payload.get("agentId"))
    templates = backend.service.store.list_card_templates(profile=agent_id)
    return {
        "agentId": agent_id,
        "templates": [_card_template_projection(template) for template in templates],
    }


async def _cards_templates_install(backend: Any, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"agentId", "template"}:
        raise ValueError("Card template install payload is invalid")
    agent_id = _card_template_agent_id(payload.get("agentId"))
    template = payload.get("template")
    if not isinstance(template, dict):
        raise ValueError("Card template install payload is invalid")
    result = backend.service.store.install_card_template(
        profile=agent_id,
        template=template,
    )
    return {
        "agentId": agent_id,
        "changed": result["changed"],
        "template": _card_template_projection(result["template"]),
    }


async def _cards_templates_remove(backend: Any, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "agentId", "templateId", "version", "sha256"
    }:
        raise ValueError("Card template removal payload is invalid")
    agent_id = _card_template_agent_id(payload.get("agentId"))
    result = backend.service.store.remove_card_template(
        profile=agent_id,
        template_id=payload.get("templateId"),
        version=payload.get("version"),
        sha256=payload.get("sha256"),
    )
    return {"agentId": agent_id, **result}


def _install_card_template_workspace_operations() -> None:
    # The template sync extension is installed into the existing finite workspace
    # controller so it inherits authenticated account encryption, request/result
    # correlation, ordered delivery, and reconnect behavior. It never enters the
    # notification service or relay journal.
    from . import link_contracts, workspace_control

    handlers = {
        "cards.templates.list": "cards_templates_list",
        "cards.templates.install": "cards_templates_install",
        "cards.templates.remove": "cards_templates_remove",
    }
    operations = frozenset((*link_contracts.WORKSPACE_OPERATIONS, *handlers))
    link_contracts.WORKSPACE_OPERATIONS = operations
    workspace_control.WORKSPACE_OPERATIONS = operations
    workspace_control.WorkspaceController._HANDLERS.update(handlers)
    setattr(workspace_control.HermesWorkspaceBackend, "cards_templates_list", _cards_templates_list)
    setattr(workspace_control.HermesWorkspaceBackend, "cards_templates_install", _cards_templates_install)
    setattr(workspace_control.HermesWorkspaceBackend, "cards_templates_remove", _cards_templates_remove)


def setup_cli(parser: Any) -> None:
    actions = parser.add_subparsers(dest="loopdy_action", required=True)

    actions.add_parser("status", help="Show provider health and registered devices")

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


_install_card_template_workspace_operations()
