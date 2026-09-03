from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn
from urllib.parse import urlsplit


MAX_DOCUMENT_BYTES = 65_536
MAX_DATA_SOURCES = 4
MAX_ELEMENTS = 80
MAX_TREE_DEPTH = 12
MAX_CHILDREN = 20
MAX_TEXT_SCALARS = 2_000
MAX_EXPRESSION_DEPTH = 8
MAX_TABLE_COLUMNS = 8
MAX_TABLE_ROWS = 50
MAX_CHART_SERIES = 6
MAX_CHART_POINTS = 120
MAX_LIST_ITEMS = 50

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
_HASH_64 = re.compile(r"^[0-9a-f]{64}$")
_HASH_32 = re.compile(r"^[0-9a-f]{32}$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

_ELEMENT_TYPES = {
    "card",
    "vstack",
    "hstack",
    "grid",
    "text",
    "metric",
    "badge",
    "progress",
    "chart",
    "table",
    "list",
    "divider",
    "spacer",
    "image",
}
_CONTAINERS = {"card", "vstack", "hstack", "grid"}
_LEAVES = _ELEMENT_TYPES - _CONTAINERS - {"list"}
_SEMANTICS = {
    "primary",
    "secondary",
    "positive",
    "warning",
    "negative",
    "accent",
    "neutral",
}
_SPACING = {"none", "xsmall", "small", "medium", "large", "xlarge"}
_TYPOGRAPHY = {"caption", "body", "callout", "headline", "title", "large_title"}
_ALIGNMENTS = {"leading", "center", "trailing"}
_FORMAT_STYLES = {
    "text",
    "integer",
    "number",
    "currency",
    "percent",
    "date",
    "time",
    "relative_date",
}
_OPERATIONS = {
    "coalesce",
    "add",
    "subtract",
    "multiply",
    "divide",
    "percent_change",
    "equal",
    "not_equal",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "and",
    "or",
    "not",
}
_LOCAL_SUFFIXES = {
    "localhost",
    "local",
    "internal",
    "home",
    "lan",
    "arpa",
}
_IMAGE_NAMES = {
    "bitcoinsign.circle.fill",
    "bolt.fill",
    "calendar",
    "chart.line.uptrend.xyaxis",
    "checkmark.circle.fill",
    "clock",
    "cloud.sun.fill",
    "drop.fill",
    "exclamationmark.triangle.fill",
    "info.circle.fill",
    "location.fill",
    "LoopdyMarkColor",
    "star.fill",
    "thermometer.medium",
    "wave.3.right.circle",
    "wind",
}


class LoopdyCardError(ValueError):
    """Stable validation error raised at every Loopdy Card trust boundary."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_json(value: object) -> str:
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
            raise LoopdyCardError(
                "invalid_number", "Non-finite numbers are not allowed"
            ) from error
        raise LoopdyCardError(
            "invalid_payload", "Card is not canonical JSON"
        ) from error
    except (TypeError, OverflowError) as error:
        raise LoopdyCardError(
            "invalid_payload", "Card is not canonical JSON"
        ) from error


def validate_card_input(
    payload: object,
    *,
    now: datetime,
    allow_live_data_for_testing: bool = False,
) -> dict[str, object]:
    reference = _utc(now, code="invalid_clock")
    encoded = canonical_json(payload)
    if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        _raise("payload_too_large", "Card exceeds the 64 KiB document limit")
    if not isinstance(payload, dict):
        _raise("invalid_payload", "Card must be an object")

    value = json.loads(encoded)
    allowed = {
        "schema",
        "version",
        "title",
        "spoken_summary",
        "importance",
        "valid_until",
        "data_sources",
        "root",
        "elements",
    }
    required = allowed - {"importance", "valid_until"}
    _object(value, allowed, required)
    if value["schema"] != "loopdy.card":
        _raise("invalid_schema", "Unsupported Loopdy Card schema")
    if isinstance(value["version"], bool) or value["version"] != 1:
        _raise("unsupported_version", "Unsupported Loopdy Card version")
    _text(value["title"])
    _text(value["spoken_summary"])
    if "importance" in value and value["importance"] not in {"normal", "important", "urgent"}:
        _raise("invalid_importance", "Card importance is invalid")
    if "valid_until" in value:
        try:
            valid_until = _timestamp(value["valid_until"])
        except LoopdyCardError as error:
            raise LoopdyCardError(
                "invalid_valid_until", "Card validity timestamp is invalid"
            ) from error
        if not reference < valid_until <= reference + timedelta(days=30):
            _raise("invalid_valid_until", "Card validity is outside thirty days")

    sources = _data_sources(value["data_sources"], reference)
    if sources and not allow_live_data_for_testing:
        _raise(
            "live_data_unavailable",
            "Live Loopdy Card data sources are not available in this release",
        )
    elements = value["elements"]
    if not isinstance(elements, dict) or not 1 <= len(elements) <= MAX_ELEMENTS:
        _raise("limit_exceeded", "Element count is outside the allowed range")
    for element_id in elements:
        _identifier(element_id)
    source_ids = {source["id"] for source in sources}
    for element_id, element in elements.items():
        _element(element_id, element, source_ids)

    root = _identifier(value["root"])
    _validate_tree(root, elements)
    return value


def render_card(payload: object, *, now: datetime) -> dict[str, object]:
    created = _utc(now, code="invalid_clock")
    validated = validate_card_input(payload, now=created)
    content_hash = hashlib.sha256(
        canonical_json(validated).encode("utf-8")
    ).hexdigest()
    result: dict[str, object] = {
        **validated,
        "content_hash": content_hash,
        "card_id": content_hash[:32],
        "created_at": _timestamp_text(created),
        "origin": "live",
    }
    if len(canonical_json(result).encode("utf-8")) > MAX_DOCUMENT_BYTES:
        _raise("payload_too_large", "Rendered card exceeds the 64 KiB document limit")
    return result


def validate_card_result(payload: object, *, now: datetime) -> dict[str, object]:
    observed = _utc(now, code="invalid_clock")
    encoded = canonical_json(payload)
    if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        _raise("payload_too_large", "Rendered card exceeds the 64 KiB document limit")
    if not isinstance(payload, dict):
        _raise("invalid_payload", "Rendered card must be an object")
    value = json.loads(encoded)
    input_keys = {
        "schema",
        "version",
        "title",
        "spoken_summary",
        "importance",
        "valid_until",
        "data_sources",
        "root",
        "elements",
    }
    renderer_keys = {"content_hash", "card_id", "created_at", "origin"}
    required_input_keys = input_keys - {"importance", "valid_until"}
    _object(value, input_keys | renderer_keys, required_input_keys | renderer_keys)

    try:
        created = _timestamp(value["created_at"])
    except LoopdyCardError as error:
        raise LoopdyCardError(
            "invalid_created_at", "Renderer creation time is invalid"
        ) from error
    if created > observed + timedelta(minutes=5):
        _raise("invalid_created_at", "Renderer creation time is in the future")
    if value["origin"] != "live":
        _raise("invalid_origin", "Renderer origin is invalid")

    card_input = {key: value[key] for key in input_keys if key in value}
    validated = validate_card_input(card_input, now=created)
    expected_hash = hashlib.sha256(
        canonical_json(validated).encode("utf-8")
    ).hexdigest()
    content_hash = value["content_hash"]
    if not isinstance(content_hash, str) or not _HASH_64.fullmatch(content_hash):
        _raise("invalid_content_hash", "Card content hash is invalid")
    if content_hash != expected_hash:
        _raise("invalid_content_hash", "Card content hash does not match its document")
    card_id = value["card_id"]
    if (
        not isinstance(card_id, str)
        or not _HASH_32.fullmatch(card_id)
        or card_id != expected_hash[:32]
    ):
        _raise("invalid_card_id", "Card identity does not match its content")
    return {
        **validated,
        "content_hash": expected_hash,
        "card_id": expected_hash[:32],
        "created_at": _timestamp_text(created),
        "origin": "live",
    }


def _data_sources(value: object, reference: datetime) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_DATA_SOURCES:
        _raise("limit_exceeded", "Data source count exceeds the limit")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for source in value:
        _object(source, {"id", "request", "response", "refresh"}, {"id", "request", "response", "refresh"})
        source_id = _identifier(source["id"])
        if source_id in seen:
            _raise("duplicate_source", "Data source IDs must be unique")
        seen.add(source_id)

        request = source["request"]
        _object(request, {"method", "url"}, {"method", "url"})
        if request["method"] != "GET":
            _raise("invalid_url", "Card data sources are GET-only")
        _public_https_url(request["url"])

        response = source["response"]
        _object(response, {"format", "root"}, {"format", "root"})
        if response["format"] != "json":
            _raise("invalid_value", "Card responses must be JSON")
        _pointer(response["root"])

        refresh = source["refresh"]
        _object(
            refresh,
            {"minimum_interval_seconds", "stale_after_seconds", "expires_at"},
            {"minimum_interval_seconds", "stale_after_seconds", "expires_at"},
        )
        interval = _integer(refresh["minimum_interval_seconds"])
        stale = _integer(refresh["stale_after_seconds"])
        if not 60 <= interval <= 3_600 or not interval <= stale <= 86_400:
            _raise("invalid_refresh", "Refresh and stale intervals are invalid")
        try:
            expires = _timestamp(refresh["expires_at"])
        except LoopdyCardError as error:
            raise LoopdyCardError(
                "invalid_expiration", "Data source expiration is invalid"
            ) from error
        if not reference < expires <= reference + timedelta(days=7):
            _raise("invalid_expiration", "Data source expiration is outside seven days")
        result.append(source)
    return result


def _element(
    element_id: str,
    value: object,
    source_ids: set[str],
) -> None:
    _object(value, {"type", "props", "children"}, {"type", "props", "children"})
    element_type = value["type"]
    if element_type not in _ELEMENT_TYPES:
        _raise("unsupported_element", f"Element {element_id} has an unsupported type")
    props = value["props"]
    if not isinstance(props, dict):
        _raise("invalid_value", f"Element {element_id} props must be an object")
    children = value["children"]
    if not isinstance(children, list):
        _raise("invalid_children", f"Element {element_id} children must be an array")
    if len(children) > MAX_CHILDREN:
        _raise("limit_exceeded", "Children per container exceed the limit")
    for child in children:
        _identifier(child)
    if element_type in _LEAVES and children:
        _raise("invalid_children", f"Element {element_id} cannot have children")
    if element_type == "list" and len(children) != 1:
        _raise("invalid_children", "A list requires exactly one template child")

    if element_type == "card":
        _props(props, {"title", "subtitle"}, {"title"})
        _text(props["title"])
        if "subtitle" in props:
            _text(props["subtitle"])
    elif element_type in {"vstack", "hstack"}:
        _props(props, {"spacing", "alignment"}, set())
        _optional_enum(props, "spacing", _SPACING)
        _optional_enum(props, "alignment", _ALIGNMENTS)
    elif element_type == "grid":
        _props(props, {"columns", "spacing", "alignment"}, {"columns"})
        if _integer(props["columns"]) not in {2, 3}:
            _raise("invalid_value", "Grid columns must be two or three")
        _optional_enum(props, "spacing", _SPACING)
        _optional_enum(props, "alignment", _ALIGNMENTS)
    elif element_type == "text":
        _props(
            props,
            {"value", "format", "typography", "color", "alignment", "line_limit"},
            {"value"},
        )
        _binding(props["value"], source_ids)
        _optional_format(props, source_ids)
        _optional_enum(props, "typography", _TYPOGRAPHY)
        _optional_enum(props, "color", _SEMANTICS)
        _optional_enum(props, "alignment", _ALIGNMENTS)
        if "line_limit" in props and not 1 <= _integer(props["line_limit"]) <= 20:
            _raise("limit_exceeded", "Text line limit is outside the allowed range")
    elif element_type == "metric":
        _props(
            props,
            {"label", "value", "format", "trend", "trend_format", "semantic"},
            {"label", "value"},
        )
        _text(props["label"])
        _binding(props["value"], source_ids)
        _optional_format(props, source_ids)
        if "trend" in props:
            _binding(props["trend"], source_ids)
        if "trend_format" in props:
            _format(props["trend_format"], source_ids)
        _optional_enum(props, "semantic", _SEMANTICS)
    elif element_type == "badge":
        _props(props, {"value", "semantic"}, {"value", "semantic"})
        _binding(props["value"], source_ids)
        _enum(props["semantic"], _SEMANTICS)
    elif element_type == "progress":
        _props(
            props,
            {"label", "value", "maximum", "format", "semantic"},
            {"label", "value", "maximum"},
        )
        _text(props["label"])
        _binding(props["value"], source_ids)
        _binding(props["maximum"], source_ids)
        _optional_format(props, source_ids)
        _optional_enum(props, "semantic", _SEMANTICS)
    elif element_type == "chart":
        _chart(props, source_ids)
    elif element_type == "table":
        _table(props, source_ids)
    elif element_type == "list":
        _props(props, {"items", "empty_text", "shows_dividers"}, {"items"})
        _source_binding(props["items"], source_ids)
        if "empty_text" in props:
            _text(props["empty_text"])
        if "shows_dividers" in props and not isinstance(props["shows_dividers"], bool):
            _raise("invalid_value", "List divider visibility must be boolean")
    elif element_type == "divider":
        _props(props, {"semantic"}, set())
        _optional_enum(props, "semantic", _SEMANTICS)
    elif element_type == "spacer":
        _props(props, {"size"}, {"size"})
        _enum(props["size"], _SPACING)
    elif element_type == "image":
        _props(
            props,
            {"name", "accessibility_label", "semantic", "scale"},
            {"name", "accessibility_label"},
        )
        _enum(props["name"], _IMAGE_NAMES)
        _text(props["accessibility_label"])
        _optional_enum(props, "semantic", _SEMANTICS)
        _optional_enum(props, "scale", {"small", "medium", "large"})


def _chart(props: dict[str, object], source_ids: set[str]) -> None:
    _props(props, {"kind", "description", "series"}, {"kind", "description", "series"})
    _enum(props["kind"], {"line", "area", "bar"})
    _text(props["description"])
    series_values = props["series"]
    if not isinstance(series_values, list) or not 1 <= len(series_values) <= MAX_CHART_SERIES:
        _raise("limit_exceeded", "Chart series count is outside the allowed range")
    seen: set[str] = set()
    for series in series_values:
        _object(series, {"id", "label", "semantic", "points"}, {"id", "label", "semantic", "points"})
        series_id = _identifier(series["id"])
        if series_id in seen:
            _raise("duplicate_element", "Chart series IDs must be unique")
        seen.add(series_id)
        _text(series["label"])
        _enum(series["semantic"], _SEMANTICS)
        points = series["points"]
        if not isinstance(points, list) or not 1 <= len(points) <= MAX_CHART_POINTS:
            _raise("limit_exceeded", "Chart point count is outside the allowed range")
        for point in points:
            _object(point, {"x", "y", "label"}, {"x", "y"})
            _binding(point["x"], source_ids)
            _binding(point["y"], source_ids)
            if "label" in point:
                _text(point["label"])


def _table(props: dict[str, object], source_ids: set[str]) -> None:
    _props(props, {"columns", "rows"}, {"columns", "rows"})
    columns = props["columns"]
    rows = props["rows"]
    if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_TABLE_COLUMNS:
        _raise("limit_exceeded", "Table column count is outside the allowed range")
    if not isinstance(rows, list) or len(rows) > MAX_TABLE_ROWS:
        _raise("limit_exceeded", "Table row count exceeds the limit")
    for column in columns:
        _object(column, {"label", "alignment", "format"}, {"label"})
        _text(column["label"])
        _optional_enum(column, "alignment", _ALIGNMENTS)
        if "format" in column:
            _format(column["format"], source_ids)
    for row in rows:
        _object(row, {"cells"}, {"cells"})
        cells = row["cells"]
        if not isinstance(cells, list) or len(cells) != len(columns):
            _raise("invalid_value", "Each table row must match its columns")
        for cell in cells:
            _binding(cell, source_ids)


def _binding(value: object, source_ids: set[str], depth: int = 0) -> None:
    if not isinstance(value, dict):
        _raise("invalid_binding", "A card value must be a binding object")
    keys = set(value)
    if keys == {"literal"}:
        literal = value["literal"]
        if isinstance(literal, str):
            _text(literal, allows_empty=True)
        elif isinstance(literal, bool) or literal is None:
            pass
        elif isinstance(literal, (int, float)):
            _finite(literal)
        else:
            _raise("invalid_binding", "Literal bindings must contain a scalar JSON value")
        return
    if keys == {"source", "pointer"}:
        _source_binding(value, source_ids)
        return
    if keys != {"expression"}:
        _raise("invalid_binding", "Binding contains unknown or missing fields")
    if depth >= MAX_EXPRESSION_DEPTH:
        _raise("limit_exceeded", "Expression nesting exceeds eight levels")
    expression = value["expression"]
    _object(expression, {"op", "arguments"}, {"op", "arguments"})
    operation = _enum(expression["op"], _OPERATIONS)
    arguments = expression["arguments"]
    if not isinstance(arguments, list) or not 1 <= len(arguments) <= 8:
        _raise("invalid_expression", "Expression argument count is invalid")
    if operation == "not" and len(arguments) != 1:
        _raise("invalid_expression", "not requires one argument")
    if operation in {"and", "or"} and len(arguments) < 2:
        _raise("invalid_expression", "Boolean aggregations require two arguments")
    if operation not in {"coalesce", "and", "or", "not"} and len(arguments) != 2:
        _raise("invalid_expression", "Binary operation requires two arguments")
    for argument in arguments:
        _binding(argument, source_ids, depth + 1)


def _source_binding(value: object, source_ids: set[str]) -> None:
    _object(value, {"source", "pointer"}, {"source", "pointer"})
    source = _identifier(value["source"])
    if source not in source_ids:
        _raise("unknown_source", "Binding references an undeclared data source")
    _pointer(value["pointer"])


def _optional_format(props: dict[str, object], source_ids: set[str]) -> None:
    if "format" in props:
        _format(props["format"], source_ids)


def _format(value: object, _source_ids: set[str]) -> None:
    _object(
        value,
        {
            "style",
            "currency",
            "currency_pointer",
            "minimum_fraction_digits",
            "maximum_fraction_digits",
        },
        {"style"},
    )
    style = _enum(value["style"], _FORMAT_STYLES)
    currency_fields = {key for key in ("currency", "currency_pointer") if key in value}
    if style == "currency":
        if len(currency_fields) != 1:
            _raise("invalid_format", "Currency format requires one currency source")
    elif currency_fields:
        _raise("invalid_format", "Currency metadata is only valid for currency format")
    if "currency" in value:
        currency = value["currency"]
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            _raise("invalid_format", "Currency must be an ISO-style code")
    if "currency_pointer" in value:
        _pointer(value["currency_pointer"])
    minimum = value.get("minimum_fraction_digits")
    maximum = value.get("maximum_fraction_digits")
    if minimum is not None and not 0 <= _integer(minimum) <= 6:
        _raise("invalid_format", "Minimum fraction digits are invalid")
    if maximum is not None and not 0 <= _integer(maximum) <= 6:
        _raise("invalid_format", "Maximum fraction digits are invalid")
    if minimum is not None and maximum is not None and minimum > maximum:
        _raise("invalid_format", "Minimum fraction digits exceed maximum")
    if (minimum is not None or maximum is not None) and style not in {
        "integer",
        "number",
        "currency",
        "percent",
    }:
        _raise("invalid_format", "Fraction digits are invalid for this format")


def _validate_tree(root: str, elements: dict[str, object]) -> None:
    if root not in elements:
        _raise("missing_root", "Root element is not defined")
    visited: set[str] = set()
    active: set[str] = set()
    stack: list[tuple[str, int, bool]] = [(root, 1, False)]
    while stack:
        element_id, depth, exiting = stack.pop()
        if exiting:
            active.remove(element_id)
            visited.add(element_id)
            continue
        if element_id in active:
            _raise("cycle", "Element graph contains a cycle")
        if element_id in visited:
            _raise("duplicate_element", "Element is referenced more than once")
        if element_id not in elements:
            _raise("invalid_children", "Element references an unknown child")
        if depth > MAX_TREE_DEPTH:
            _raise("limit_exceeded", "Element tree exceeds twelve levels")
        active.add(element_id)
        stack.append((element_id, depth, True))
        children = elements[element_id]["children"]
        for child in reversed(children):
            stack.append((child, depth + 1, False))
    unreachable = set(elements) - visited
    if unreachable:
        _raise("unreachable_element", "Card contains unreachable elements")


def _public_https_url(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 2_048:
        _raise("invalid_url", "Data source URL is invalid or too long")
    if any(character.isspace() or ord(character) < 32 for character in value):
        _raise("invalid_url", "Data source URL contains whitespace or controls")
    try:
        components = urlsplit(value)
        port = components.port
    except ValueError as error:
        raise LoopdyCardError("invalid_url", "Data source URL is malformed") from error
    if (
        components.scheme.lower() != "https"
        or not components.netloc
        or components.username is not None
        or components.password is not None
        or components.fragment
        or port not in {None, 443}
        or "%" in components.netloc
    ):
        _raise("invalid_url", "Data source URL violates the public GET policy")
    raw_host = components.hostname
    if raw_host is None:
        _raise("invalid_url", "Data source URL requires a public DNS host")
    host = raw_host.lower().rstrip(".")
    try:
        host.encode("ascii")
    except UnicodeEncodeError as error:
        raise LoopdyCardError("invalid_url", "Data source host must be ASCII DNS") from error
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _raise("invalid_url", "Literal IP hosts are forbidden")
    labels = host.split(".")
    if (
        len(labels) < 2
        or any(not _DNS_LABEL.fullmatch(label) for label in labels)
        or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
        or any(host == suffix or host.endswith(f".{suffix}") for suffix in _LOCAL_SUFFIXES)
    ):
        _raise("invalid_url", "Data source host is not a public DNS name")
    return value


def _pointer(value: object) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 2_048:
        _raise("invalid_pointer", "JSON Pointer is invalid or too long")
    if value == "":
        return value
    if not value.startswith("/"):
        _raise("invalid_pointer", "JSON Pointer must be empty or begin with a slash")
    for token in value.split("/")[1:]:
        index = 0
        while index < len(token):
            if token[index] == "~":
                if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                    _raise("invalid_pointer", "JSON Pointer escape is invalid")
                index += 2
            else:
                index += 1
    return value


def _object(value: object, allowed: set[str], required: set[str]) -> None:
    if not isinstance(value, dict):
        _raise("invalid_value", "Expected an object")
    unknown = set(value) - allowed
    if unknown:
        _raise("unknown_field", "Object contains an unknown field")
    if required - set(value):
        _raise("missing_field", "Object is missing a required field")


def _props(value: dict[str, object], allowed: set[str], required: set[str]) -> None:
    _object(value, allowed, required)


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        _raise("invalid_identifier", "Identifier is invalid")
    return value


def _text(value: object, *, allows_empty: bool = False) -> str:
    if not isinstance(value, str):
        _raise("invalid_value", "Expected text")
    if (not allows_empty and not value) or len(value) > MAX_TEXT_SCALARS:
        _raise("limit_exceeded", "Text is outside the 2,000-scalar limit")
    for scalar in value:
        codepoint = ord(scalar)
        if 0xD800 <= codepoint <= 0xDFFF:
            _raise("invalid_value", "Text contains an invalid Unicode scalar")
        if codepoint < 32 and scalar not in {"\n", "\t"}:
            _raise("invalid_value", "Text contains a forbidden control character")
    return value


def _finite(value: int | float) -> int | float:
    if isinstance(value, bool) or not math.isfinite(value):
        _raise("invalid_number", "Expected a finite number")
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _raise("invalid_value", "Expected an integer")
    return value


def _enum(value: object, choices: set[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        _raise("invalid_value", "Value is not in the allowlist")
    return value


def _optional_enum(
    value: dict[str, object], key: str, choices: set[str]
) -> None:
    if key in value:
        _enum(value[key], choices)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        _raise("invalid_value", "Expected an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _raise("invalid_value", "Expected an RFC 3339 timestamp")
    if parsed.tzinfo is None:
        _raise("invalid_value", "Timestamp requires a timezone")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime, *, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _raise(code, "Clock must include a timezone")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _raise(code: str, message: str) -> NoReturn:
    raise LoopdyCardError(code, message)
