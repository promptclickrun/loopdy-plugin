import json
import inspect
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .generative_ui import V2_COMPONENTS, render_envelope, render_v2_envelope
from .loopdy_cards import canonical_json as canonical_card_json
from .loopdy_cards import render_card
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


def _card_parameters() -> dict[str, Any]:
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "spec"
        / "loopdy-card-v1.schema.json"
    )
    portable = json.loads(schema_path.read_text(encoding="utf-8"))
    return {
        "type": portable["type"],
        "properties": portable["properties"],
        "required": portable["required"],
        "additionalProperties": portable["additionalProperties"],
        "$defs": portable["$defs"],
    }


def _card_handler(now: Callable[[], datetime]):
    def handle(payload, **_kwargs):
        return canonical_card_json(render_card(payload, now=now()))

    return handle


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


def _template_store(store: Any) -> Any:
    if store is None or not all(
        hasattr(store, name)
        for name in ("list_card_templates", "get_card_template")
    ):
        raise ValueError("Loopdy card template storage is unavailable")
    return store


def _template_search_handler(*, store: Any, profile: str):
    def handle(payload, **_kwargs):
        if not isinstance(payload, dict) or set(payload) != {"query"}:
            raise ValueError("template search arguments must contain only query")
        query = payload.get("query")
        if not isinstance(query, str) or len(query) > 120:
            raise ValueError("template search query is invalid")
        needle = query.strip().casefold()
        templates = []
        for template in _template_store(store).list_card_templates(profile=profile):
            searchable = " ".join(
                str(template.get(key) or "")
                for key in ("id", "name", "summary", "author")
            ).casefold()
            if needle and needle not in searchable:
                continue
            templates.append({
                key: template[key]
                for key in (
                    "id", "version", "name", "summary", "author", "license",
                    "minimum_card_version", "sha256"
                )
            })
        return canonical_card_json({"templates": templates})

    return handle


def _template_get_handler(*, store: Any, profile: str):
    def handle(payload, **_kwargs):
        if not isinstance(payload, dict) or set(payload) != {"template_id"}:
            raise ValueError("template get arguments must contain only template_id")
        template_id = payload.get("template_id")
        if not isinstance(template_id, str):
            raise ValueError("template id is invalid")
        template = _template_store(store).get_card_template(
            profile=profile,
            template_id=template_id,
        )
        if template is None:
            raise ValueError("Loopdy card template was not found")
        return canonical_card_json({"template": template})

    return handle


def _template_render_handler(
    *,
    store: Any,
    profile: str,
    now: Callable[[], datetime],
):
    def handle(payload, **_kwargs):
        if not isinstance(payload, dict) or set(payload) != {"template_id", "parameters"}:
            raise ValueError("template render arguments are invalid")
        template_id = payload.get("template_id")
        parameters = payload.get("parameters")
        if not isinstance(template_id, str) or not isinstance(parameters, dict):
            raise ValueError("template render arguments are invalid")
        template = _template_store(store).get_card_template(
            profile=profile,
            template_id=template_id,
        )
        if template is None:
            raise ValueError("Loopdy card template was not found")
        values = _validated_template_parameters(template["parameters_schema"], parameters)
        document = _substitute_template_parameters(
            template["document"],
            values,
            declared_names=set(template["parameters_schema"]["properties"]),
        )
        # This deliberately ends on the same renderer-owned validator as
        # loopdy_render_card; templates do not gain a parallel rendering path.
        return canonical_card_json(render_card(document, now=now()))

    return handle


def _validated_template_parameters(schema: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    properties = schema["properties"]
    required = set(schema["required"])
    if set(values) - set(properties) or not required.issubset(values):
        raise ValueError("template parameters do not match the declared schema")
    normalized: dict[str, Any] = {}
    for name, property_schema in properties.items():
        if name not in values:
            if "default" in property_schema:
                normalized[name] = property_schema["default"]
            continue
        value = values[name]
        kind = property_schema["type"]
        valid_type = (
            (kind == "string" and isinstance(value, str))
            or (kind == "integer" and type(value) is int)
            or (kind == "number" and type(value) in {int, float})
            or (kind == "boolean" and type(value) is bool)
        )
        if not valid_type or ("enum" in property_schema and value not in property_schema["enum"]):
            raise ValueError(f"template parameter {name} is invalid")
        if kind == "string" and (
            len(value) < int(property_schema.get("minLength", 0))
            or len(value) > int(property_schema.get("maxLength", 2_000))
        ):
            raise ValueError(f"template parameter {name} is invalid")
        if kind in {"integer", "number"} and (
            value < property_schema.get("minimum", value)
            or value > property_schema.get("maximum", value)
        ):
            raise ValueError(f"template parameter {name} is invalid")
        normalized[name] = value
    return normalized


_TEMPLATE_SLOT = re.compile(r"\{\{([A-Za-z][A-Za-z0-9_-]{0,63})\}\}")
_TEMPLATE_STRUCTURAL_KEYS = frozenset({
    "schema", "version", "type", "id", "source", "pointer", "op", "operation",
    "method", "root", "format", "children", "content_hash", "card_id", "origin",
    "created_at", "valid_until", "minimum_interval_seconds", "stale_after_seconds",
    "expires_at", "refresh",
})


def _substitute_template_parameters(
    value: Any,
    parameters: dict[str, Any],
    *,
    declared_names: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("template document is invalid")
    result = json.loads(canonical_card_json(value))
    for key in ("title", "spoken_summary"):
        result[key] = _substitute_template_literal(
            result[key], parameters, declared_names
        )
    for key, item in result.items():
        if key not in {"title", "spoken_summary", "elements", "data_sources"}:
            _reject_template_slots(key)
            _reject_template_slots(item)

    elements = result.get("elements")
    if not isinstance(elements, dict):
        raise ValueError("template document is invalid")
    for element_id, element in elements.items():
        _reject_template_slots(element_id)
        if not isinstance(element, dict):
            raise ValueError("template document is invalid")
        for key, item in element.items():
            if key == "props":
                element[key] = _substitute_template_literal(
                    item, parameters, declared_names
                )
            else:
                _reject_template_slots(key)
                _reject_template_slots(item)

    sources = result.get("data_sources")
    if not isinstance(sources, list):
        raise ValueError("template document is invalid")
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("template document is invalid")
        for key, item in source.items():
            if key != "request":
                _reject_template_slots(key)
                _reject_template_slots(item)
        request = source.get("request")
        if not isinstance(request, dict):
            raise ValueError("template document is invalid")
        for key, item in request.items():
            if key != "url":
                _reject_template_slots(key)
                _reject_template_slots(item)
        request["url"] = _substitute_template_url(
            request.get("url"), parameters, declared_names
        )
    return result


def _substitute_template_literal(
    value: Any,
    parameters: dict[str, Any],
    declared_names: set[str],
) -> Any:
    if isinstance(value, list):
        return [
            _substitute_template_literal(item, parameters, declared_names)
            for item in value
        ]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            _reject_template_slots(key)
            if key in _TEMPLATE_STRUCTURAL_KEYS:
                _reject_template_slots(item)
                result[key] = item
            elif key == "url":
                result[key] = _substitute_template_url(
                    item, parameters, declared_names
                )
            else:
                result[key] = _substitute_template_literal(
                    item, parameters, declared_names
                )
        return result
    if not isinstance(value, str):
        return value
    return _substitute_template_string(
        value,
        parameters,
        declared_names,
        preserves_value_type=True,
    )


def _substitute_template_string(
    value: str,
    parameters: dict[str, Any],
    declared_names: set[str],
    *,
    preserves_value_type: bool,
) -> Any:
    names = set(_TEMPLATE_SLOT.findall(value))
    if not names:
        return value
    if not names.issubset(declared_names):
        raise ValueError("template contains an unsafe undeclared parameter slot")
    if value == f"{{{{{next(iter(names))}}}}}" and len(names) == 1:
        parameter = parameters.get(next(iter(names)), _MISSING_TEMPLATE_PARAMETER)
        if parameter is _MISSING_TEMPLATE_PARAMETER:
            raise ValueError("template parameter is invalid")
        return parameter if preserves_value_type else _template_parameter_text(parameter)
    result = value
    for name in sorted(names):
        if name not in parameters:
            raise ValueError("template parameter is invalid")
        result = result.replace(f"{{{{{name}}}}}", _template_parameter_text(parameters[name]))
    return result


def _substitute_template_url(
    value: Any,
    parameters: dict[str, Any],
    declared_names: set[str],
) -> str:
    if not isinstance(value, str):
        raise ValueError("template URL is invalid")
    parts = urlsplit(value)
    for structural in (parts.scheme, parts.netloc, parts.path, parts.fragment):
        _reject_template_slots(structural)
    query = []
    for name, item in parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False):
        _reject_template_slots(name)
        query.append((
            name,
            _substitute_template_string(
                item,
                parameters,
                declared_names,
                preserves_value_type=False,
            ),
        ))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _reject_template_slots(value: Any) -> None:
    if isinstance(value, str) and _TEMPLATE_SLOT.search(value):
        raise ValueError("template contains an unsafe structural parameter slot")
    if isinstance(value, list):
        for item in value:
            _reject_template_slots(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_template_slots(key)
            _reject_template_slots(item)


def _template_parameter_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if type(value) is bool:
        return "true" if value else "false"
    return str(value)


_MISSING_TEMPLATE_PARAMETER = object()


def _template_tool_description(action: str) -> str:
    return (
        f"{action} profile-installed Loopdy Card templates for the direct callable native "
        "Loopdy renderer. Call it when visible in the current tool list. When progressively "
        "disclosed, use tool_search, tool_describe, and tool_call to invoke this exact tool."
    )


def _marketplace_publish_parameters() -> dict[str, Any]:
    metadata = _strict_object(
        {
            "title": {"type": "string", "minLength": 1, "maxLength": 80},
            "summary": {"type": "string", "minLength": 1, "maxLength": 240},
            "description": {"type": "string", "maxLength": 8_000},
            "tags": {
                "type": "array",
                "maxItems": 8,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1, "maxLength": 24},
            },
            "publicAuthorName": {
                "type": "string",
                "minLength": 1,
                "maxLength": 80,
            },
            "license": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$",
            },
            "declaredCapabilities": {
                "type": "array",
                "maxItems": 16,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": "^[A-Za-z][A-Za-z0-9._:-]{0,63}$",
                },
            },
        },
        [
            "title",
            "summary",
            "description",
            "tags",
            "publicAuthorName",
            "license",
            "declaredCapabilities",
        ],
    )
    return _strict_object(
        {
            "agentId": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$",
            },
            "kind": {"type": "string", "enum": ["theme", "card", "skill"]},
            "sourceId": {"type": "string", "minLength": 1, "maxLength": 128},
            "validateOnly": {"type": "boolean"},
            "metadata": metadata,
            "idempotencyKey": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{16,96}$",
            },
        },
        [
            "agentId",
            "kind",
            "sourceId",
            "validateOnly",
            "metadata",
            "idempotencyKey",
        ],
    )


def _marketplace_publish_handler(publisher: Any):
    async def handle(payload, **_kwargs):
        if publisher is None or not callable(getattr(publisher, "prepare_upload", None)):
            raise ValueError("Loopdy Marketplace publishing is unavailable")
        result = publisher.prepare_upload(payload)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, dict):
            raise ValueError("Loopdy Marketplace publishing returned an invalid result")
        return json.dumps(
            result, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )

    return handle


def register(
    ctx,
    *,
    store: Any = None,
    profile: str | None = None,
    marketplace_publisher: Any = None,
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
        name="loopdy_render_card",
        toolset="loopdy",
        schema={
            "name": "loopdy_render_card",
            "description": (
                "Render one bounded static native Loopdy Card from the finite component catalog. "
                "All displayed values must be embedded in the payload and data_sources must be empty; "
                "live Card data refresh is unavailable in this release. This is the direct callable native Loopdy renderer. "
                "Call this renderer directly when it is visible in the current tool list. When Hermes has progressively "
                "disclosed it and it is absent, use the official tool_search, tool_describe, "
                "and tool_call bridge to invoke this exact renderer; do not substitute or "
                "wrap another tool. For scheduler-owned Loopdy Inbox delivery, your final response must be "
                "exactly the returned JSON envelope, with no prose or code fence. The renderer tool result "
                "alone is not delivered by cron. In a normal interactive chat, do not repeat the JSON."
            ),
            "parameters": _card_parameters(),
        },
        handler=_card_handler(clock),
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
    ctx.register_tool(
        name="loopdy_marketplace_prepare_upload",
        toolset="loopdy",
        schema={
            "name": "loopdy_marketplace_prepare_upload",
            "description": (
                "Validate one explicitly selected Loopdy theme attachment, installed card "
                "template, or profile-owned skill and, only when the current user request "
                "authorizes that exact source and destination, prepare a private marketplace "
                "draft for review in Loopdy My Uploads. Use validateOnly first. This tool "
                "cannot submit or publish a listing."
            ),
            "parameters": _marketplace_publish_parameters(),
        },
        handler=_marketplace_publish_handler(marketplace_publisher),
        is_async=True,
    )
    if store is not None and all(
        hasattr(store, name)
        for name in ("list_card_templates", "get_card_template")
    ):
        template_tools = (
            (
                "loopdy_search_card_templates",
                _template_tool_description("Search"),
                _strict_object({"query": {"type": "string", "maxLength": 120}}, ["query"]),
                _template_search_handler(store=store, profile=selected_profile),
            ),
            (
                "loopdy_get_card_template",
                _template_tool_description("Get"),
                _strict_object(
                    {"template_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"}},
                    ["template_id"],
                ),
                _template_get_handler(store=store, profile=selected_profile),
            ),
            (
                "loopdy_render_card_template",
                _template_tool_description("Render"),
                _strict_object(
                    {
                        "template_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
                        "parameters": {
                            "type": "object",
                            "maxProperties": 32,
                            "additionalProperties": True,
                        },
                    },
                    ["template_id", "parameters"],
                ),
                _template_render_handler(
                    store=store,
                    profile=selected_profile,
                    now=clock,
                ),
            ),
        )
        for name, description, parameters, handler in template_tools:
            ctx.register_tool(
                name=name,
                toolset="loopdy",
                schema={
                    "name": name,
                    "description": description,
                    "parameters": parameters,
                },
                handler=handler,
            )
