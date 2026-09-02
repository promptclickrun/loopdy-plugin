import json
from datetime import datetime, timezone
from typing import Any, Callable

from .generative_ui import V2_COMPONENTS, render_envelope, render_v2_envelope
from .store import form_action_response


def _parameters(component):
    fields = {
        "schema": {"type": "string", "const": "loopdy.generative_ui"},
        "version": {"type": "integer", "const": 1},
        "component": {"type": "string", "const": component},
        "title": {"type": "string", "maxLength": 500},
    }
    if component == "summary":
        fields["body"] = {"type": "string", "maxLength": 500}
    elif component == "metrics":
        fields["metrics"] = {"type": "object", "maxProperties": 20}
    elif component in ("list", "timeline"):
        key = "items" if component == "list" else "steps"
        fields[key] = {"type": "array", "maxItems": 20}
    return {"type": "object", "properties": fields, "additionalProperties": False}


def _handler(tool_name):
    def handle(payload, **_kwargs):
        if not isinstance(payload, dict):
            raise ValueError("renderer arguments must be an object")
        return json.dumps(render_envelope(tool_name, payload), ensure_ascii=False)
    return handle


def _v2_parameters(component: str) -> dict[str, Any]:
    provenance = _strict_object(
        {
            "source_name": _text(80),
            "source_timestamp": {"type": "string", "format": "date-time"},
            "retrieved_at": {"type": "string", "format": "date-time"},
            "valid_until": {"type": "string", "format": "date-time"},
            "cache_status": {"type": "string", "enum": ["live", "cached", "stale", "historical"]},
            "age_seconds": {"type": "integer", "minimum": 0, "maximum": 31_536_000},
            "attribution": _text(160),
        },
        # The renderer owns age_seconds.  It is accepted as optional model
        # metadata for backwards compatibility, then derived from the signed
        # source/retrieval timestamp facts before the result is returned.
        ["source_name", "source_timestamp", "retrieved_at", "cache_status"],
    )
    properties = {
        "schema": {"type": "string", "const": "loopdy.generative_ui"},
        "version": {"type": "integer", "const": 2},
        "component": {"type": "string", "const": component},
        "title": _text(120),
        "subtitle": _text(240),
        "data": _v2_data_schema(component),
    }
    required = ["schema", "version", "component", "title", "data"]
    if component != "form":
        properties["provenance"] = provenance
        required.append("provenance")
    return _strict_object(properties, required)


def _v2_data_schema(component: str) -> dict[str, Any]:
    identifier = {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,39}$"}
    if component == "weather_forecast":
        condition = ["clear", "partly_cloudy", "cloudy", "rain", "snow", "sleet", "storm", "fog", "wind", "smoke", "unknown"]
        current = _strict_object({"condition_code": {"type": "string", "enum": condition}, "condition_label": _text(80), "temperature": _number(-150, 150), "feels_like": _number(-150, 150), "humidity_percent": _integer(0, 100), "wind_speed": _number(0, 500), "wind_direction": _text(16)}, ["condition_code", "condition_label", "temperature"])
        period = _strict_object({"id": identifier, "label": _text(40), "start_at": {"type": "string", "format": "date-time"}, "end_at": {"type": "string", "format": "date-time"}, "condition_code": {"type": "string", "enum": condition}, "condition_label": _text(80), "high": _number(-150, 150), "low": _number(-150, 150), "precipitation_percent": _integer(0, 100)}, ["id", "label", "start_at", "end_at", "condition_code", "condition_label", "precipitation_percent"])
        return _strict_object({"location": _text(120), "timezone": _text(64), "units": {"type": "string", "enum": ["us", "metric"]}, "current": current, "periods": {"type": "array", "minItems": 1, "maxItems": 14, "items": period}}, ["location", "timezone", "units", "current", "periods"])
    if component == "sports_game":
        team = _strict_object({"id": identifier, "name": _text(80), "abbreviation": {"type": "string", "pattern": "^[A-Z0-9]{1,8}$"}, "home": {"type": "boolean"}, "score": {"type": ["integer", "null"], "minimum": 0, "maximum": 999}, "record": _text(24)}, ["id", "name", "abbreviation", "home", "score"])
        return _strict_object({"league": {"type": "string", "enum": ["nfl", "nba", "wnba", "mlb", "nhl", "ncaaf", "ncaam", "ncaaw", "mls", "other"]}, "league_label": _text(40), "status": {"type": "string", "enum": ["scheduled", "live", "final", "postponed", "cancelled"]}, "start_at": {"type": "string", "format": "date-time"}, "period_label": _text(20), "clock": _text(20), "venue": _text(120), "teams": {"type": "array", "minItems": 2, "maxItems": 2, "items": team}, "highlights": {"type": "array", "maxItems": 8, "items": _text(160)}}, ["league", "status", "start_at", "teams"])
    if component == "stock_quote":
        return _strict_object({"symbol": {"type": "string", "pattern": "^[A-Z0-9.^-]{1,12}$"}, "exchange": _text(20), "company_name": _text(120), "currency": {"type": "string", "pattern": "^[A-Z]{3}$"}, "market_status": {"type": "string", "enum": ["pre_market", "open", "after_hours", "closed", "halted"]}, "price": _number(0, 1e12), "change": _number(-1e12, 1e12), "change_percent": _number(-1e6, 1e6), "previous_close": _number(0, 1e12), "session_open": _number(0, 1e12), "day_high": _number(0, 1e12), "day_low": _number(0, 1e12), "volume": _integer(0, 1_000_000_000_000)}, ["symbol", "exchange", "company_name", "currency", "market_status", "price", "change", "change_percent"])
    if component == "chart":
        return _chart_schema(6, 60)
    if component == "dashboard":
        metric = _strict_object({"id": identifier, "label": _text(80), "value_text": _text(60), "secondary_text": _text(100), "status": {"type": "string", "enum": ["neutral", "positive", "warning", "negative"]}, "status_label": _text(60)}, ["id", "label", "value_text", "status", "status_label"])
        return _strict_object({"description": _text(300), "metrics": {"type": "array", "minItems": 1, "maxItems": 12, "items": metric}, "charts": {"type": "array", "maxItems": 2, "items": _chart_schema(3, 40)}}, ["description", "metrics"])
    option = _strict_object({"id": identifier, "label": _text(80)}, ["id", "label"])
    options = {"type": "array", "minItems": 1, "maxItems": 20, "items": option}
    common = {"id": identifier, "label": _text(100), "help_text": _text(240), "required": {"type": "boolean"}}
    required = ["id", "kind", "label", "required"]
    fields = [
        _strict_object({**common, "kind": {"const": "text"}, "default": {"type": "string", "maxLength": 500}, "min_length": _integer(0, 500), "max_length": _integer(1, 500)}, required),
        _strict_object({**common, "kind": {"const": "textarea"}, "default": {"type": "string", "maxLength": 2000}, "min_length": _integer(0, 2000), "max_length": _integer(1, 2000)}, required),
        _strict_object({**common, "kind": {"const": "select"}, "options": options, "default": identifier}, [*required, "options"]),
        _strict_object({**common, "kind": {"const": "multi_select"}, "options": options, "max_selected": _integer(1, 10), "default": {"type": "array", "maxItems": 10, "uniqueItems": True, "items": identifier}}, [*required, "options", "max_selected"]),
        _strict_object({**common, "kind": {"const": "toggle"}, "default": {"type": "boolean"}}, required),
        _strict_object({**common, "kind": {"const": "integer"}, "min": _integer(-1_000_000_000_000, 1_000_000_000_000), "max": _integer(-1_000_000_000_000, 1_000_000_000_000), "step": _integer(1, 1_000_000_000), "default": _integer(-1_000_000_000_000, 1_000_000_000_000)}, required),
        _strict_object({**common, "kind": {"const": "decimal"}, "min": _number(-1e12, 1e12), "max": _number(-1e12, 1e12), "step": _number(0.000001, 1e9), "default": _number(-1e12, 1e12)}, required),
        _strict_object({**common, "kind": {"const": "date"}, "min": {"type": "string", "format": "date"}, "max": {"type": "string", "format": "date"}, "default": {"type": "string", "format": "date"}}, required),
    ]
    return _strict_object({"description": _text(300), "submit_label": _text(40), "fields": {"type": "array", "minItems": 1, "maxItems": 12, "items": {"oneOf": fields}}}, ["description", "submit_label", "fields"])


def _chart_schema(max_series: int, max_points: int) -> dict[str, Any]:
    identifier = {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,39}$"}
    point = _strict_object({"x": {"type": "string", "maxLength": 40}, "y": _number(-1e12, 1e12), "label": _text(80)}, ["x", "y"])
    series = _strict_object({"id": identifier, "label": _text(60), "semantic": {"type": "string", "enum": ["primary", "comparison", "positive", "warning", "negative", "neutral"]}, "status_label": _text(60), "points": {"type": "array", "minItems": 1, "maxItems": max_points, "items": point}}, ["id", "label", "semantic", "status_label", "points"])
    x_axis = _strict_object({"label": _text(60), "kind": {"type": "string", "enum": ["category", "time"]}, "unit": _text(20)}, ["label", "kind"])
    y_axis = _strict_object({"label": _text(60), "unit": _text(20), "min": _number(-1e12, 1e12), "max": _number(-1e12, 1e12)}, ["label"])
    return _strict_object({"chart_type": {"type": "string", "enum": ["line", "bar", "area"]}, "description": _text(300), "x_axis": x_axis, "y_axis": y_axis, "series": {"type": "array", "minItems": 1, "maxItems": max_series, "items": series}}, ["chart_type", "description", "x_axis", "y_axis", "series"])


def _strict_object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def _text(maximum: int) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": maximum}


def _number(minimum: float, maximum: float) -> dict[str, Any]:
    return {"type": "number", "minimum": minimum, "maximum": maximum}


def _integer(minimum: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


def _v2_handler(
    tool_name: str,
    *,
    store: Any,
    profile: str,
    now: Callable[[], datetime],
    request_id_factory: Callable[[], str] | None,
):
    def handle(payload, **kwargs):
        created = now()
        value = render_v2_envelope(
            tool_name,
            payload,
            now=created,
            profile=profile,
            session_id=str(kwargs.get("session_id") or ""),
            request_id_factory=request_id_factory,
        )
        if value["component"] == "form":
            if store is None or not hasattr(store, "create_form_request"):
                raise ValueError("Loopdy form storage is unavailable")
            store.create_form_request(
                request_id=value["action"]["request_id"],
                profile=value["action"]["owner"]["profile"],
                session_id=value["action"]["owner"]["session_id"],
                form_schema=value["data"],
                content_hash=value["content_hash"],
                created_at=int(created.timestamp()),
                expires_at=int(created.timestamp()) + 300,
            )
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return handle


def _await_handler(*, store: Any, profile: str, now: Callable[[], datetime]):
    def handle(payload, **kwargs):
        if not isinstance(payload, dict) or set(payload) != {"request_id"}:
            raise ValueError("await arguments must contain only request_id")
        if store is None or not hasattr(store, "consume_form_response"):
            raise ValueError("Loopdy form storage is unavailable")
        try:
            value = store.consume_form_response(
                request_id=payload["request_id"],
                profile=profile,
                session_id=str(kwargs.get("session_id") or ""),
                now=int(now().timestamp()),
            )
        except ValueError:
            value = form_action_response(
                payload.get("request_id", ""), "", "error", "request_not_found"
            )
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return handle


def register(
    ctx,
    *,
    store: Any = None,
    profile: str | None = None,
    now: Callable[[], datetime] | None = None,
    request_id_factory: Callable[[], str] | None = None,
):
    selected_profile = str(profile or getattr(ctx, "profile_name", "default") or "default")
    clock = now or (lambda: datetime.now(timezone.utc))
    for component in ("summary", "metrics", "list", "timeline"):
        name = f"loopdy_render_{component}"
        ctx.register_tool(
            name=name,
            toolset="loopdy",
            schema={
                "name": name,
                "description": (
                    f"Render a bounded Loopdy {component} display-only card. "
                    "This is a direct callable native Loopdy renderer. Call it directly "
                    "when it is visible in the current tool list. When Hermes has "
                    "progressively disclosed it and it is absent, use the official "
                    "tool_search, tool_describe, and tool_call bridge to invoke this "
                    "exact renderer; do not substitute or wrap another tool."
                ),
                "parameters": _parameters(component),
            },
            handler=_handler(name),
        )
    for component in V2_COMPONENTS:
        name = f"loopdy_render_{component}"
        ctx.register_tool(
            name=name,
            toolset="loopdy",
            schema={
                "name": name,
                "description": (
                    f"Render a bounded Loopdy {component} native v2 card. This is a direct callable "
                    "native Loopdy renderer. Call it directly when it is visible in the current "
                    "tool list. When Hermes has progressively disclosed it and it is absent, use "
                    "the official tool_search, tool_describe, and tool_call bridge to invoke this "
                    "exact renderer; do not substitute or wrap another tool."
                ),
                "parameters": _v2_parameters(component),
            },
            handler=_v2_handler(
                name,
                store=store,
                profile=selected_profile,
                now=clock,
                request_id_factory=request_id_factory,
            ),
        )
    ctx.register_tool(
        name="loopdy_await_form_response",
        toolset="loopdy",
        schema={
            "name": "loopdy_await_form_response",
            "description": (
                "Wait for one exact-session Loopdy form response. Call this tool directly; it must "
                "not be routed through tool_search, tool_describe, or tool_call."
            ),
            "parameters": _strict_object(
                {"request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}},
                ["request_id"],
            ),
        },
        handler=_await_handler(store=store, profile=selected_profile, now=clock),
    )
