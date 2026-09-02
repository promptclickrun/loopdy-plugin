import hashlib
import json
import math
import re
import secrets
import unicodedata
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, NoReturn

MAX_BYTES = 16_384
MAX_ITEMS = 20
MAX_STRING = 500
MAX_NUMBER = 1_000_000_000
COMPONENT_FIELDS = {
    "summary": {"schema", "version", "component", "title", "body"},
    "metrics": {"schema", "version", "component", "title", "metrics"},
    "list": {"schema", "version", "component", "title", "items"},
    "timeline": {"schema", "version", "component", "title", "steps"},
}
FORBIDDEN = {"url", "style", "html", "javascript", "js", "route", "routes", "module", "native", "action", "actions"}


def _check(value, depth=0):
    if depth > 4:
        raise ValueError("payload nesting exceeds limit")
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise ValueError("string exceeds limit")
    elif isinstance(value, (int, float)) and abs(value) > MAX_NUMBER:
        raise ValueError("number exceeds limit")
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ValueError("item count exceeds limit")
        for item in value:
            _check(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN:
                raise ValueError("unsupported field")
            _check(item, depth + 1)


def validate_render_payload(payload):
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported generative UI version")
    component = payload.get("component")
    if component not in COMPONENT_FIELDS or set(payload) - COMPONENT_FIELDS[component]:
        raise ValueError("unsupported component field")
    if component == "metrics" and not isinstance(payload.get("metrics"), dict):
        raise ValueError("metrics must be an object")
    if component in {"list", "timeline"} and not isinstance(payload.get("items" if component == "list" else "steps"), list):
        raise ValueError("items must be a list")
    if component == "summary" and "body" in payload and not isinstance(payload["body"], str):
        raise ValueError("summary body must be text")
    _check(payload)
    if len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_BYTES:
        raise ValueError("payload exceeds limit")
    return payload


def render_envelope(tool_name, payload):
    expected = {"loopdy_render_" + component for component in COMPONENT_FIELDS}
    if tool_name not in expected:
        raise ValueError("unsupported renderer tool")
    value = validate_render_payload(payload)
    if value["component"] != tool_name.removeprefix("loopdy_render_"):
        raise ValueError("tool/component mismatch")
    return {"schema": "loopdy.generative_ui", "version": 1, **value}


V2_MAX_BYTES = 32_768
ACTION_MAX_BYTES = 8_192
V2_COMPONENTS = (
    "weather_forecast",
    "sports_game",
    "stock_quote",
    "chart",
    "dashboard",
    "form",
)
V2_FORBIDDEN = {
    "url", "uri", "href", "style", "styles", "css", "html", "javascript",
    "js", "route", "routes", "module", "native", "command", "shell", "rpc",
    "method", "endpoint", "headers", "token", "secret", "password", "script",
    "eval", "action", "actions",
}
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
_SYMBOL = re.compile(r"^[A-Z0-9.^-]{1,12}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_ABBREVIATION = re.compile(r"^[A-Z0-9]{1,8}$")
_TIMEZONE = re.compile(r"^[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$")
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


class GenerativeUIError(ValueError):
    """Stable public validation class for native Generative UI payloads."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except ValueError as error:
        if "Out of range float" in str(error):
            raise GenerativeUIError("invalid_number", "Non-finite numbers are not allowed") from error
        raise GenerativeUIError("invalid_payload", "Payload is not canonical JSON") from error
    except TypeError as error:
        raise GenerativeUIError("invalid_payload", "Payload is not canonical JSON") from error


def parse_v2_json(raw: str | bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise GenerativeUIError("duplicate_key", "Duplicate JSON keys are not allowed")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _value: _raise("invalid_number", "Non-finite numbers are not allowed"))
    except GenerativeUIError:
        raise
    except (TypeError, json.JSONDecodeError) as error:
        raise GenerativeUIError("invalid_json", "Payload must be a JSON object") from error
    if not isinstance(value, dict):
        raise GenerativeUIError("invalid_payload", "Payload must be a JSON object")
    return value


def render_v2_envelope(
    tool_name: str,
    payload: dict[str, Any],
    *,
    now: datetime | None = None,
    profile: str = "default",
    session_id: str = "",
    request_id_factory: Callable[[], str] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise GenerativeUIError("invalid_payload", "Renderer arguments must be an object")
    _payload_size(payload, V2_MAX_BYTES)
    expected_component = tool_name.removeprefix("loopdy_render_")
    if tool_name != f"loopdy_render_{expected_component}" or expected_component not in V2_COMPONENTS:
        raise GenerativeUIError("unsupported_component", "Unsupported renderer tool")
    allowed = {"schema", "version", "component", "title", "subtitle", "data"}
    if expected_component != "form":
        allowed.add("provenance")
    _object(payload, allowed, {"schema", "version", "component", "title", "data"})
    if payload["schema"] != "loopdy.generative_ui":
        raise GenerativeUIError("invalid_schema", "Unsupported Generative UI schema")
    if payload["version"] != 2 or isinstance(payload["version"], bool):
        raise GenerativeUIError("unsupported_version", "Unsupported Generative UI version")
    component = payload["component"]
    if component not in V2_COMPONENTS:
        raise GenerativeUIError("unsupported_component", "Unsupported Generative UI component")
    if component != expected_component:
        raise GenerativeUIError("component_mismatch", "Tool and component do not match")
    _global_check(payload)

    created = _utc(now or datetime.now(timezone.utc))
    normalized: dict[str, Any] = {
        "schema": "loopdy.generative_ui",
        "version": 2,
        "component": component,
        "title": _string(payload["title"], 1, 120),
        "data": _validate_component(component, payload["data"]),
    }
    if "subtitle" in payload:
        normalized["subtitle"] = _string(payload["subtitle"], 1, 240)
    if component != "form":
        if "provenance" not in payload:
            raise GenerativeUIError("missing_field", "Current data cards require provenance")
        normalized["provenance"] = _provenance(payload["provenance"], created)

    content_hash = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    result = {
        **normalized,
        "content_hash": content_hash,
        "created_at": _timestamp_text(created),
        "origin": "live",
    }
    if component == "form":
        owner_profile = _string(str(profile or "").strip(), 1, 80)
        owner_session = _string(str(session_id or "").strip(), 1, 180) if str(session_id or "").strip() else ""
        if not owner_session:
            raise GenerativeUIError("owner_required", "A host session is required for forms")
        request_id = (request_id_factory or (lambda: secrets.token_hex(16)))()
        if not isinstance(request_id, str) or not _HEX_32.fullmatch(request_id):
            raise GenerativeUIError("internal_error", "Request ID generation failed")
        result["card_id"] = request_id
        result["action"] = {
            "kind": "submit_form",
            "request_id": request_id,
            "owner": {"profile": owner_profile, "session_id": owner_session},
            "expires_at": _timestamp_text(created + timedelta(seconds=300)),
        }
    else:
        result["card_id"] = content_hash[:32]
    _payload_size(result, V2_MAX_BYTES)
    return result


def validate_rendered_envelope(value: Any) -> dict[str, Any]:
    """Validate a renderer result before it crosses a native-client boundary."""

    if not isinstance(value, dict):
        raise GenerativeUIError("invalid_payload", "Renderer result must be an object")
    version = value.get("version")
    if version == 1:
        if value.get("schema") != "loopdy.generative_ui":
            raise GenerativeUIError("invalid_schema", "Unsupported Generative UI schema")
        normalized = validate_render_payload(value)
        return json.loads(canonical_json(normalized))
    if version != 2 or isinstance(version, bool):
        raise GenerativeUIError("unsupported_version", "Unsupported Generative UI version")

    _payload_size(value, V2_MAX_BYTES)
    _global_check(value)
    component = value.get("component")
    if component not in V2_COMPONENTS:
        raise GenerativeUIError("unsupported_component", "Unsupported Generative UI component")
    allowed = {
        "schema", "version", "component", "title", "subtitle", "data",
        "provenance", "content_hash", "created_at", "origin", "card_id", "action",
    }
    required = {
        "schema", "version", "component", "title", "data", "content_hash",
        "created_at", "origin", "card_id",
    }
    if component == "form":
        required.add("action")
    else:
        required.add("provenance")
    _object(value, allowed, required)
    if value["schema"] != "loopdy.generative_ui" or value["origin"] != "live":
        raise GenerativeUIError("invalid_schema", "Unsupported Generative UI result")

    created = _timestamp(value["created_at"])
    normalized: dict[str, Any] = {
        "schema": "loopdy.generative_ui",
        "version": 2,
        "component": component,
        "title": _string(value["title"], 1, 120),
        "data": _validate_component(component, value["data"]),
    }
    if "subtitle" in value:
        normalized["subtitle"] = _string(value["subtitle"], 1, 240)
    if component != "form":
        normalized["provenance"] = _provenance(
            value["provenance"],
            created,
        )
    content_hash = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    if value["content_hash"] != content_hash:
        raise GenerativeUIError("invalid_content_hash", "Generative UI content hash is invalid")

    result = {
        **normalized,
        "content_hash": content_hash,
        "created_at": _timestamp_text(created),
        "origin": "live",
    }
    if component == "form":
        action = value["action"]
        _object(action, {"kind", "request_id", "owner", "expires_at"}, {"kind", "request_id", "owner", "expires_at"})
        if action["kind"] != "submit_form":
            raise GenerativeUIError("invalid_value", "Unsupported Generative UI action")
        request_id = _string(action["request_id"], 32, 32)
        if not _HEX_32.fullmatch(request_id) or value["card_id"] != request_id:
            raise GenerativeUIError("invalid_value", "Form request identity is invalid")
        owner = action["owner"]
        _object(owner, {"profile", "session_id"}, {"profile", "session_id"})
        normalized_owner = {
            "profile": _string(owner["profile"], 1, 80),
            "session_id": _string(owner["session_id"], 1, 180),
        }
        expires = _timestamp(action["expires_at"])
        if not created < expires <= created + timedelta(minutes=5):
            raise GenerativeUIError("invalid_value", "Form expiration is invalid")
        result["card_id"] = request_id
        result["action"] = {
            "kind": "submit_form",
            "request_id": request_id,
            "owner": normalized_owner,
            "expires_at": _timestamp_text(expires),
        }
    else:
        if "action" in value or value["card_id"] != content_hash[:32]:
            raise GenerativeUIError("invalid_value", "Display card identity is invalid")
        result["card_id"] = content_hash[:32]
    _payload_size(result, V2_MAX_BYTES)
    return result


def validate_submission_values(form_data: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(values, dict):
        raise GenerativeUIError("invalid_value", "Form values must be an object")
    _payload_size(values, ACTION_MAX_BYTES)
    validated_form = _form(form_data)
    fields = {field["id"]: field for field in validated_form["fields"]}
    if set(values) - set(fields):
        raise GenerativeUIError("invalid_value", "Form contains an unknown field")
    result: dict[str, Any] = {}
    for field_id in sorted(fields):
        field = fields[field_id]
        if field_id not in values:
            if field["required"]:
                raise GenerativeUIError("invalid_value", "A required form field is missing")
            continue
        result[field_id] = _submitted_value(field, values[field_id])
    return result


def _validate_component(component: str, data: Any) -> dict[str, Any]:
    return {
        "weather_forecast": _weather,
        "sports_game": _sports,
        "stock_quote": _stock,
        "chart": lambda value: _chart(value, 6, 60, 240),
        "dashboard": _dashboard,
        "form": _form,
    }[component](data)


def _weather(value: Any) -> dict[str, Any]:
    _object(value, {"location", "timezone", "units", "current", "periods"}, {"location", "timezone", "units", "current", "periods"})
    timezone_name = _string(value["timezone"], 1, 64)
    if not _TIMEZONE.fullmatch(timezone_name):
        _raise("invalid_value", "Timezone must be an IANA-style identifier")
    units = _enum(value["units"], {"us", "metric"})
    current = value["current"]
    current_allowed = {"condition_code", "condition_label", "temperature", "feels_like", "humidity_percent", "wind_speed", "wind_direction"}
    _object(current, current_allowed, {"condition_code", "condition_label", "temperature"})
    result_current = {
        "condition_code": _enum(current["condition_code"], {"clear", "partly_cloudy", "cloudy", "rain", "snow", "sleet", "storm", "fog", "wind", "smoke", "unknown"}),
        "condition_label": _string(current["condition_label"], 1, 80),
        "temperature": _number(current["temperature"], -150, 150),
    }
    for key in ("feels_like", "wind_speed"):
        if key in current:
            result_current[key] = _number(current[key], -150 if key == "feels_like" else 0, 150 if key == "feels_like" else 500)
    if "humidity_percent" in current:
        result_current["humidity_percent"] = _integer(current["humidity_percent"], 0, 100)
    if "wind_direction" in current:
        result_current["wind_direction"] = _string(current["wind_direction"], 1, 16)
    periods = _array(value["periods"], 1, 14)
    result_periods = []
    previous = None
    ids = set()
    for period in periods:
        allowed = {"id", "label", "start_at", "end_at", "condition_code", "condition_label", "high", "low", "precipitation_percent"}
        _object(period, allowed, {"id", "label", "start_at", "end_at", "condition_code", "condition_label", "precipitation_percent"})
        period_id = _identifier_v2(period["id"])
        if period_id in ids:
            _raise("invalid_value", "Weather period IDs must be unique")
        ids.add(period_id)
        start = _timestamp(period["start_at"])
        end = _timestamp(period["end_at"])
        if start >= end:
            _raise("invalid_value", "Weather period start must precede end")
        if previous is not None and start <= previous:
            _raise("invalid_order", "Weather periods must be strictly ordered")
        previous = start
        item = {
            "id": period_id, "label": _string(period["label"], 1, 40),
            "start_at": _timestamp_text(start), "end_at": _timestamp_text(end),
            "condition_code": _enum(period["condition_code"], {"clear", "partly_cloudy", "cloudy", "rain", "snow", "sleet", "storm", "fog", "wind", "smoke", "unknown"}),
            "condition_label": _string(period["condition_label"], 1, 80),
            "precipitation_percent": _integer(period["precipitation_percent"], 0, 100),
        }
        for key in ("high", "low"):
            if key in period:
                item[key] = _number(period[key], -150, 150)
        if "high" in item and "low" in item and item["low"] > item["high"]:
            _raise("invalid_value", "Weather low cannot exceed high")
        result_periods.append(item)
    return {"location": _string(value["location"], 1, 120), "timezone": timezone_name, "units": units, "current": result_current, "periods": result_periods}


def _sports(value: Any) -> dict[str, Any]:
    allowed = {"league", "league_label", "status", "start_at", "period_label", "clock", "venue", "teams", "highlights"}
    _object(value, allowed, {"league", "status", "start_at", "teams"})
    league = _enum(value["league"], {"nfl", "nba", "wnba", "mlb", "nhl", "ncaaf", "ncaam", "ncaaw", "mls", "other"})
    if (league == "other") != ("league_label" in value):
        _raise("invalid_value", "league_label is required only for other leagues")
    game_status = _enum(value["status"], {"scheduled", "live", "final", "postponed", "cancelled"})
    if "period_label" in value and game_status not in {"live", "final"}:
        _raise("invalid_value", "period_label is allowed only for live or final games")
    if "clock" in value and game_status != "live":
        _raise("invalid_value", "clock is allowed only for live games")
    teams = _array(value["teams"], 2, 2)
    normalized_teams = []
    ids, abbreviations = set(), set()
    for team in teams:
        _object(team, {"id", "name", "abbreviation", "home", "score", "record"}, {"id", "name", "abbreviation", "home", "score"})
        team_id = _identifier_v2(team["id"])
        abbreviation = _string(team["abbreviation"], 1, 8)
        if not _ABBREVIATION.fullmatch(abbreviation) or team_id in ids or abbreviation in abbreviations:
            _raise("invalid_value", "Team IDs and abbreviations must be valid and unique")
        ids.add(team_id); abbreviations.add(abbreviation)
        score = team["score"]
        if score is not None:
            score = _integer(score, 0, 999)
        if game_status in {"live", "final"} and score is None:
            _raise("invalid_value", "Live and final games require scores")
        item = {"id": team_id, "name": _string(team["name"], 1, 80), "abbreviation": abbreviation, "home": _boolean(team["home"]), "score": score}
        if "record" in team: item["record"] = _string(team["record"], 1, 24)
        normalized_teams.append(item)
    if sum(1 for team in normalized_teams if team["home"]) != 1:
        _raise("invalid_value", "Exactly one team must be home")
    result = {"league": league, "status": game_status, "start_at": _timestamp_text(_timestamp(value["start_at"])), "teams": sorted(normalized_teams, key=lambda team: team["home"])}
    for key, maximum in (("league_label", 40), ("period_label", 20), ("clock", 20), ("venue", 120)):
        if key in value: result[key] = _string(value[key], 1, maximum)
    if "highlights" in value: result["highlights"] = [_string(item, 1, 160) for item in _array(value["highlights"], 0, 8)]
    return result


def _stock(value: Any) -> dict[str, Any]:
    allowed = {"symbol", "exchange", "company_name", "currency", "market_status", "price", "change", "change_percent", "previous_close", "session_open", "day_high", "day_low", "volume"}
    required = {"symbol", "exchange", "company_name", "currency", "market_status", "price", "change", "change_percent"}
    _object(value, allowed, required)
    symbol = _string(value["symbol"], 1, 12); currency = _string(value["currency"], 3, 3)
    if not _SYMBOL.fullmatch(symbol) or not _CURRENCY.fullmatch(currency): _raise("invalid_value", "Stock symbol or currency is invalid")
    result = {"symbol": symbol, "exchange": _string(value["exchange"], 1, 20), "company_name": _string(value["company_name"], 1, 120), "currency": currency, "market_status": _enum(value["market_status"], {"pre_market", "open", "after_hours", "closed", "halted"}), "price": _number(value["price"], 0, 1e12), "change": _number(value["change"], -1e12, 1e12), "change_percent": _number(value["change_percent"], -1e6, 1e6)}
    for key in ("previous_close", "session_open", "day_high", "day_low"):
        if key in value: result[key] = _number(value[key], 0, 1e12)
    if "volume" in value: result["volume"] = _integer(value["volume"], 0, 1_000_000_000_000)
    if "day_low" in result and "day_high" in result and result["day_low"] > result["day_high"]: _raise("invalid_value", "Stock day low cannot exceed day high")
    return result


def _chart(value: Any, max_series: int, max_points: int, max_total: int) -> dict[str, Any]:
    _object(value, {"chart_type", "description", "x_axis", "y_axis", "series"}, {"chart_type", "description", "x_axis", "y_axis", "series"})
    x_axis = value["x_axis"]; y_axis = value["y_axis"]
    _object(x_axis, {"label", "kind", "unit"}, {"label", "kind"}); _object(y_axis, {"label", "unit", "min", "max"}, {"label"})
    x_kind = _enum(x_axis["kind"], {"category", "time"})
    normalized_x = {"label": _string(x_axis["label"], 1, 60), "kind": x_kind}
    normalized_y = {"label": _string(y_axis["label"], 1, 60)}
    for axis, normalized in ((x_axis, normalized_x), (y_axis, normalized_y)):
        if "unit" in axis: normalized["unit"] = _string(axis["unit"], 1, 20)
    for key in ("min", "max"):
        if key in y_axis: normalized_y[key] = _number(y_axis[key], -1e12, 1e12)
    if "min" in normalized_y and "max" in normalized_y and normalized_y["min"] >= normalized_y["max"]: _raise("invalid_value", "Y axis minimum must be below maximum")
    series_values = _array(value["series"], 1, max_series)
    normalized_series = []; ids = set(); labels = set(); total = 0
    for series in series_values:
        _object(series, {"id", "label", "semantic", "status_label", "points"}, {"id", "label", "semantic", "status_label", "points"})
        series_id = _identifier_v2(series["id"]); label = _string(series["label"], 1, 60)
        if series_id in ids or label in labels: _raise("invalid_value", "Chart series IDs and labels must be unique")
        ids.add(series_id); labels.add(label)
        points = _array(series["points"], 1, max_points); total += len(points)
        normalized_points = []; previous = None
        for point in points:
            _object(point, {"x", "y", "label"}, {"x", "y"})
            x = _timestamp_text(_timestamp(point["x"])) if x_kind == "time" else _string(point["x"], 1, 40)
            if x_kind == "time" and previous is not None and x <= previous: _raise("invalid_order", "Chart time points must be strictly ascending")
            previous = x
            normalized_point = {"x": x, "y": _number(point["y"], -1e12, 1e12)}
            if "label" in point: normalized_point["label"] = _string(point["label"], 1, 80)
            normalized_points.append(normalized_point)
        normalized_series.append({"id": series_id, "label": label, "semantic": _enum(series["semantic"], {"primary", "comparison", "positive", "warning", "negative", "neutral"}), "status_label": _string(series["status_label"], 1, 60), "points": normalized_points})
    if total > max_total: _raise("limit_exceeded", "Chart aggregate point limit exceeded")
    return {"chart_type": _enum(value["chart_type"], {"line", "bar", "area"}), "description": _string(value["description"], 1, 300), "x_axis": normalized_x, "y_axis": normalized_y, "series": normalized_series}


def _dashboard(value: Any) -> dict[str, Any]:
    _object(value, {"description", "metrics", "charts"}, {"description", "metrics"})
    metrics = _array(value["metrics"], 1, 12); normalized_metrics = []; ids = set()
    for metric in metrics:
        _object(metric, {"id", "label", "value_text", "secondary_text", "status", "status_label"}, {"id", "label", "value_text", "status", "status_label"})
        metric_id = _identifier_v2(metric["id"])
        if metric_id in ids: _raise("invalid_value", "Dashboard metric IDs must be unique")
        ids.add(metric_id)
        item = {"id": metric_id, "label": _string(metric["label"], 1, 80), "value_text": _string(metric["value_text"], 1, 60), "status": _enum(metric["status"], {"neutral", "positive", "warning", "negative"}), "status_label": _string(metric["status_label"], 1, 60)}
        if "secondary_text" in metric: item["secondary_text"] = _string(metric["secondary_text"], 1, 100)
        normalized_metrics.append(item)
    result = {"description": _string(value["description"], 1, 300), "metrics": normalized_metrics}
    if "charts" in value: result["charts"] = [_chart(chart, 3, 40, 120) for chart in _array(value["charts"], 0, 2)]
    return result


def _form(value: Any) -> dict[str, Any]:
    _object(value, {"description", "submit_label", "fields"}, {"description", "submit_label", "fields"})
    fields = _array(value["fields"], 1, 12); normalized = []; ids = set()
    for field in fields:
        kind = field.get("kind") if isinstance(field, dict) else None
        common = {"id", "kind", "label", "help_text", "required"}
        kind_fields = {
            "text": {"default", "min_length", "max_length"}, "textarea": {"default", "min_length", "max_length"},
            "select": {"options", "default"}, "multi_select": {"options", "max_selected", "default"},
            "toggle": {"default"}, "integer": {"min", "max", "step", "default"},
            "decimal": {"min", "max", "step", "default"}, "date": {"min", "max", "default"},
        }
        if kind not in kind_fields: _raise("invalid_value", "Unsupported form field kind")
        _object(field, common | kind_fields[kind], {"id", "kind", "label", "required"} | ({"options"} if kind in {"select", "multi_select"} else set()) | ({"max_selected"} if kind == "multi_select" else set()))
        field_id = _identifier_v2(field["id"])
        if field_id in ids: _raise("invalid_value", "Form field IDs must be unique")
        ids.add(field_id)
        item = {"id": field_id, "kind": kind, "label": _string(field["label"], 1, 100), "required": _boolean(field["required"])}
        if "help_text" in field: item["help_text"] = _string(field["help_text"], 1, 240)
        if kind in {"text", "textarea"}:
            maximum = 500 if kind == "text" else 2000
            minimum_length = _integer(field.get("min_length", 0), 0, maximum)
            maximum_length = _integer(field.get("max_length", maximum), 1, maximum)
            if minimum_length > maximum_length: _raise("invalid_value", "Minimum length cannot exceed maximum length")
            if "min_length" in field: item["min_length"] = minimum_length
            if "max_length" in field: item["max_length"] = maximum_length
            if "default" in field:
                item["default"] = _string(field["default"], 0, maximum, textarea=kind == "textarea")
                if not minimum_length <= len(item["default"]) <= maximum_length: _raise("invalid_value", "Default text is outside the declared limits")
        elif kind in {"select", "multi_select"}:
            options = _array(field["options"], 1, 20); option_ids = set(); normalized_options = []
            for option in options:
                _object(option, {"id", "label"}, {"id", "label"}); option_id = _identifier_v2(option["id"])
                if option_id in option_ids: _raise("invalid_value", "Form option IDs must be unique")
                option_ids.add(option_id); normalized_options.append({"id": option_id, "label": _string(option["label"], 1, 80)})
            item["options"] = normalized_options
            if kind == "select" and "default" in field:
                if field["default"] not in option_ids: _raise("invalid_value", "Select default was not offered")
                item["default"] = field["default"]
            if kind == "multi_select":
                maximum_selected = _integer(field["max_selected"], 1, min(10, len(options))); item["max_selected"] = maximum_selected
                if "default" in field:
                    defaults = _array(field["default"], 0, maximum_selected)
                    if len(set(defaults)) != len(defaults) or any(option not in option_ids for option in defaults): _raise("invalid_value", "Multi-select defaults are invalid")
                    item["default"] = list(defaults)
        elif kind == "toggle":
            if "default" in field: item["default"] = _boolean(field["default"])
        elif kind in {"integer", "decimal"}:
            convert = _integer if kind == "integer" else _number
            lower = convert(field["min"], -1e12, 1e12) if "min" in field else None
            upper = convert(field["max"], -1e12, 1e12) if "max" in field else None
            if lower is not None: item["min"] = lower
            if upper is not None: item["max"] = upper
            if lower is not None and upper is not None and lower > upper: _raise("invalid_value", "Numeric minimum cannot exceed maximum")
            if "step" in field:
                step = convert(field["step"], 1 if kind == "integer" else 0.000001, 1e9)
                if step <= 0: _raise("invalid_value", "Numeric step must be positive")
                item["step"] = step
            if "default" in field:
                default = convert(field["default"], -1e12, 1e12)
                if (lower is not None and default < lower) or (upper is not None and default > upper): _raise("invalid_value", "Numeric default is outside the declared range")
                item["default"] = default
        elif kind == "date":
            parsed = {}
            for key in ("min", "max", "default"):
                if key in field: parsed[key] = _date_text(field[key]); item[key] = parsed[key]
            if "min" in parsed and "max" in parsed and parsed["min"] > parsed["max"]: _raise("invalid_value", "Date minimum cannot exceed maximum")
            if "default" in parsed and (("min" in parsed and parsed["default"] < parsed["min"]) or ("max" in parsed and parsed["default"] > parsed["max"])): _raise("invalid_value", "Date default is outside the declared range")
        normalized.append(item)
    return {"description": _string(value["description"], 1, 300), "submit_label": _string(value["submit_label"], 1, 40), "fields": normalized}


def _submitted_value(field: dict[str, Any], value: Any) -> Any:
    kind = field["kind"]
    if kind in {"text", "textarea"}:
        maximum = field.get("max_length", 500 if kind == "text" else 2000); minimum = field.get("min_length", 0)
        text = _string(value, minimum, maximum, textarea=kind == "textarea")
        return text
    if kind == "select":
        if value not in {option["id"] for option in field["options"]}: _raise("invalid_value", "Select value was not offered")
        return value
    if kind == "multi_select":
        selected = _array(value, 0, field["max_selected"])
        if len(set(selected)) != len(selected) or any(item not in {option["id"] for option in field["options"]} for item in selected): _raise("invalid_value", "Multi-select value is invalid")
        return list(selected)
    if kind == "toggle": return _boolean(value)
    if kind in {"integer", "decimal"}:
        converted = (_integer if kind == "integer" else _number)(value, -1e12, 1e12)
        if ("min" in field and converted < field["min"]) or ("max" in field and converted > field["max"]): _raise("invalid_value", "Numeric value is outside the declared range")
        if "step" in field:
            base = field.get("min", 0)
            quotient = (Decimal(str(converted)) - Decimal(str(base))) / Decimal(str(field["step"]))
            if quotient != quotient.to_integral_value(): _raise("invalid_value", "Numeric value does not match the declared step")
        return converted
    if kind == "date":
        converted = _date_text(value)
        if ("min" in field and converted < field["min"]) or ("max" in field and converted > field["max"]): _raise("invalid_value", "Date value is outside the declared range")
        return converted
    _raise("invalid_value", "Unsupported form field kind")


def _provenance(
    value: Any,
    created: datetime,
) -> dict[str, Any]:
    allowed = {"source_name", "source_timestamp", "retrieved_at", "valid_until", "cache_status", "age_seconds", "attribution"}
    _object(value, allowed, {"source_name", "source_timestamp", "retrieved_at", "cache_status"})
    source = _timestamp(value["source_timestamp"]); retrieved = _timestamp(value["retrieved_at"])
    if source > retrieved or retrieved > created + timedelta(minutes=5): _raise("invalid_freshness", "Provenance timestamps are inconsistent")
    valid_until = _timestamp(value["valid_until"]) if "valid_until" in value else None
    if valid_until is not None and valid_until < retrieved: _raise("invalid_freshness", "Provenance validity precedes retrieval")
    # `age_seconds` is supplied by a model and can become stale while the
    # turn is still running. Validate its type, but derive the displayed age
    # from the timestamp facts at the renderer boundary so transport or tool
    # delay cannot invalidate an otherwise truthful card.
    if "age_seconds" in value:
        # Older model prompts included this presentation field. Continue to
        # type-check it when present, but never trust it as a freshness fact.
        _integer(value["age_seconds"], 0, 31_536_000)
    expected_age = math.floor((created - source).total_seconds())
    if expected_age > 31_536_000: _raise("invalid_freshness", "Provenance source is outside the supported freshness window")
    age = max(0, expected_age)
    result = {"source_name": _string(value["source_name"], 1, 80), "source_timestamp": _timestamp_text(source), "retrieved_at": _timestamp_text(retrieved), "cache_status": _enum(value["cache_status"], {"live", "cached", "stale", "historical"}), "age_seconds": age}
    if valid_until is not None: result["valid_until"] = _timestamp_text(valid_until)
    if "attribution" in value: result["attribution"] = _string(value["attribution"], 1, 160)
    return result


def _global_check(value: Any, depth: int = 0) -> None:
    if depth > 6: _raise("limit_exceeded", "Payload nesting exceeds limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str): _raise("invalid_payload", "Object keys must be strings")
            if key.lower() in V2_FORBIDDEN: _raise("forbidden_field", "Executable or routing fields are forbidden")
            _global_check(item, depth + 1)
    elif isinstance(value, list):
        # Collection wrappers do not consume object-nesting budget. Otherwise
        # the frozen dashboard -> chart -> series -> point union cannot fit.
        for item in value: _global_check(item, depth)
    elif isinstance(value, str): _string(value, 0, max(500, len(value)))
    elif isinstance(value, bool) or value is None: return
    elif isinstance(value, (int, float)): _number(value, -1e12, 1e12)
    else: _raise("invalid_payload", "Payload contains a non-JSON value")


def _object(value: Any, allowed: set[str], required: set[str]) -> None:
    if not isinstance(value, dict): _raise("invalid_value", "Expected an object")
    unknown = set(value) - allowed
    if unknown: _raise("unknown_field", "Object contains an unknown field")
    if required - set(value): _raise("missing_field", "Object is missing a required field")


def _array(value: Any, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list): _raise("invalid_value", "Expected an array")
    if not minimum <= len(value) <= maximum: _raise("limit_exceeded", "Array length is outside the allowed range")
    return value


def _string(value: Any, minimum: int, maximum: int, *, textarea: bool = False) -> str:
    if not isinstance(value, str): _raise("invalid_string", "Expected text")
    normalized = unicodedata.normalize("NFC", value)
    if not minimum <= len(normalized) <= maximum: _raise("invalid_string", "Text length is outside the allowed range")
    for character in normalized:
        if ord(character) < 32 and not (textarea and character in {"\n", "\t"}): _raise("invalid_string", "Control characters are not allowed")
    return normalized


def _number(value: Any, minimum: float, maximum: float) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value): _raise("invalid_number", "Expected a finite number")
    if abs(value) > 1_000_000_000_000 or not minimum <= value <= maximum: _raise("invalid_number", "Number is outside the allowed range")
    try: decimal = Decimal(str(value)).normalize()
    except InvalidOperation: _raise("invalid_number", "Number is invalid")
    if decimal.as_tuple().exponent < -6: _raise("invalid_number", "Number has too many fractional digits")
    return int(value) if decimal == decimal.to_integral_value() else value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum: _raise("invalid_value", "Expected a bounded integer")
    return value


def _boolean(value: Any) -> bool:
    if not isinstance(value, bool): _raise("invalid_value", "Expected a boolean")
    return value


def _enum(value: Any, choices: set[str]) -> str:
    if not isinstance(value, str) or value not in choices: _raise("invalid_value", "Value is not in the allowlist")
    return value


def _identifier_v2(value: Any) -> str:
    normalized = _string(value, 1, 40)
    if not _ID.fullmatch(normalized): _raise("invalid_value", "Identifier is invalid")
    return normalized


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value): _raise("invalid_value", "Expected an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: _raise("invalid_value", "Expected an RFC3339 timestamp")
    if parsed.tzinfo is None: _raise("invalid_value", "Timestamp must include a timezone")
    return _utc(parsed)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None: _raise("invalid_value", "Host clock must include a timezone")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp_text(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _date_text(value: Any) -> str:
    if not isinstance(value, str): _raise("invalid_value", "Expected an ISO date")
    try: return date.fromisoformat(value).isoformat()
    except ValueError: _raise("invalid_value", "Expected an ISO date")


def _payload_size(value: Any, maximum: int) -> None:
    if len(canonical_json(value).encode("utf-8")) > maximum: _raise("payload_too_large", "Payload exceeds the byte limit")


def _raise(code: str, message: str) -> NoReturn:
    raise GenerativeUIError(code, message)
