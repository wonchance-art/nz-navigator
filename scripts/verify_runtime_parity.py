#!/usr/bin/env python3
"""Verify claim-registry values against safely parsed inline runtime constants."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SCHEMA_VERSION = 1
REQUIRED_BINDING_FIELDS = (
    "claimId",
    "edition",
    "page",
    "runtimePath",
    "type",
    "unit",
    "transform",
)
EDITION_META = {
    "nz": {"page": "nz/index.html", "country": "NZ", "locale": "ko"},
    "ja": {"page": "ja/index.html", "country": "NZ", "locale": "ja"},
    "ca": {"page": "ca/index.html", "country": "CA", "locale": "ko"},
    "au": {"page": "au/index.html", "country": "AU", "locale": "ko"},
}
VALUE_TYPES = frozenset({"number", "string", "array", "object", "boolean", "null"})
TRANSFORMS = frozenset(
    {
        "identity",
        "multiply",
        "sum",
        "joinRange",
        "extractRange",
        "serializeBrackets",
    }
)
BOUNDARY_KINDS = frozenset({"rate", "insurance", "age", "duration"})
PROVENANCE_FIELDS = frozenset({"sourcePath", "dates"})
PROVENANCE_DATE_FIELDS = frozenset({"runtimePath", "claimField"})
CLAIM_DATE_FIELDS = frozenset(
    {"verifiedAt", "effectiveFrom", "effectiveTo", "currentAsOf"}
)
IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
NUMBER_RE = re.compile(
    r"[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?"
)
RANGE_RE = re.compile(
    r"([+-]?\d+(?:\.\d+)?)\s*[–~〜～-]\s*([+-]?\d+(?:\.\d+)?)"
)


@dataclass(frozen=True)
class RuntimeIssue:
    code: str
    claim_id: str
    edition: str
    runtime_path: str
    actual: Any
    expected: Any
    fix: str

    def render(self) -> str:
        return (
            f"ERROR code={self.code} claim={self.claim_id} "
            f"edition={self.edition} runtimePath={self.runtime_path} "
            f"actual={_display(self.actual)} expected={_display(self.expected)}\n"
            f"  Fix: {self.fix}"
        )


@dataclass
class RuntimeReport:
    issues: list[RuntimeIssue] = field(default_factory=list)
    checked_bindings: int = 0
    checked_provenance_sources: int = 0
    checked_provenance_dates: int = 0
    boundary_cases: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues


class LiteralParseError(ValueError):
    pass


class RuntimePathError(ValueError):
    pass


class ProvenanceValueError(ValueError):
    pass


def _display(value: Any) -> str:
    try:
        return json.dumps(
            _json_value(value), ensure_ascii=False, sort_keys=True
        )
    except (TypeError, ValueError):
        return repr(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        if not value.is_finite():
            return str(value)
        if value == value.to_integral():
            return int(value)
        return float(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _canonical_decimal(value: Decimal) -> str:
    if not value.is_finite():
        return str(value)
    if value == 0:
        return "0"
    rendered = format(value.normalize(), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _as_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        try:
            return Decimal(str(value))
        except InvalidOperation:
            return None
    return None


def _normalize_json_value(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float, Decimal)):
        number = _as_decimal(value)
        return number if number is not None else value
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _normalize_json_value(item)
            for key, item in value.items()
        }
    return value


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, Decimal):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _non_finite_path(value: Any, path: str = "$") -> str | None:
    if isinstance(value, Decimal):
        return None if value.is_finite() else path
    if isinstance(value, list):
        for index, item in enumerate(value):
            found = _non_finite_path(item, f"{path}[{index}]")
            if found:
                return found
    if isinstance(value, dict):
        for key, item in value.items():
            found = _non_finite_path(item, f"{path}.{key}")
            if found:
                return found
    return None


def _iso_date(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", value
    ):
        raise ProvenanceValueError("expected an ISO YYYY-MM-DD string")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ProvenanceValueError("date is not a real calendar day") from exc
    return parsed.isoformat()


def _normalized_source_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ProvenanceValueError("expected a non-empty source URL string")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProvenanceValueError(f"malformed URL: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ProvenanceValueError("source URL scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ProvenanceValueError("source URL must not contain userinfo")
    if parsed.hostname is None:
        raise ProvenanceValueError("source URL must contain a host")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProvenanceValueError("source URL host is invalid") from exc
    if ":" in host:
        host = f"[{host}]"
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path
    return urlunsplit(
        (scheme, netloc, path, parsed.query, parsed.fragment)
    )


def _is_provenance_path_spec(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        or isinstance(value, list)
        and len(value) >= 2
        and all(isinstance(item, str) and item for item in value)
    )


def _provenance_paths(value: str | list[str]) -> list[str]:
    return value if isinstance(value, list) else [value]


class JSLiteralParser:
    """Parse a deliberately small JavaScript data-literal subset."""

    def __init__(self, source: str, start: int = 0) -> None:
        self.source = source
        self.pos = start

    def parse(self) -> Any:
        value = self._parse_value()
        self._skip_space_and_comments()
        return value

    def _error(self, message: str) -> LiteralParseError:
        line = self.source.count("\n", 0, self.pos) + 1
        column = self.pos - self.source.rfind("\n", 0, self.pos)
        return LiteralParseError(f"{message} at line {line}, column {column}")

    def _skip_space_and_comments(self) -> None:
        while self.pos < len(self.source):
            if self.source[self.pos].isspace():
                self.pos += 1
                continue
            if self.source.startswith("//", self.pos):
                newline = self.source.find("\n", self.pos + 2)
                self.pos = len(self.source) if newline < 0 else newline + 1
                continue
            if self.source.startswith("/*", self.pos):
                end = self.source.find("*/", self.pos + 2)
                if end < 0:
                    raise self._error("unterminated block comment")
                self.pos = end + 2
                continue
            break

    def _parse_value(self) -> Any:
        self._skip_space_and_comments()
        if self.pos >= len(self.source):
            raise self._error("expected a value")
        char = self.source[self.pos]
        if char == "{":
            return self._parse_object()
        if char == "[":
            return self._parse_array()
        if char in {"'", '"', "`"}:
            return self._parse_string()
        number = NUMBER_RE.match(self.source, self.pos)
        if number:
            self.pos = number.end()
            try:
                return Decimal(number.group(0))
            except InvalidOperation as exc:
                raise self._error("invalid number") from exc
        identifier = IDENTIFIER_RE.match(self.source, self.pos)
        if identifier:
            self.pos = identifier.end()
            name = identifier.group(0)
            values = {
                "true": True,
                "false": False,
                "null": None,
                "Infinity": Decimal("Infinity"),
                "NaN": Decimal("NaN"),
            }
            if name in values:
                return values[name]
            raise self._error(
                f"unsupported identifier {name!r}; only data literals are allowed"
            )
        raise self._error(f"unexpected character {char!r}")

    def _parse_object(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        self.pos += 1
        while True:
            self._skip_space_and_comments()
            if self._consume("}"):
                return result
            if self.pos >= len(self.source):
                raise self._error("unterminated object")
            if self.source[self.pos] in {"'", '"', "`"}:
                key = self._parse_string()
            else:
                match = IDENTIFIER_RE.match(self.source, self.pos)
                if not match:
                    raise self._error("expected an object key")
                key = match.group(0)
                self.pos = match.end()
            self._skip_space_and_comments()
            if not self._consume(":"):
                raise self._error("expected ':' after object key")
            result[key] = self._parse_value()
            self._skip_space_and_comments()
            if self._consume("}"):
                return result
            if not self._consume(","):
                raise self._error("expected ',' or '}' in object")
            self._skip_space_and_comments()
            if self._consume("}"):
                return result

    def _parse_array(self) -> list[Any]:
        result: list[Any] = []
        self.pos += 1
        while True:
            self._skip_space_and_comments()
            if self._consume("]"):
                return result
            if self.pos >= len(self.source):
                raise self._error("unterminated array")
            result.append(self._parse_value())
            self._skip_space_and_comments()
            if self._consume("]"):
                return result
            if not self._consume(","):
                raise self._error("expected ',' or ']' in array")
            self._skip_space_and_comments()
            if self._consume("]"):
                return result

    def _parse_string(self) -> str:
        quote = self.source[self.pos]
        self.pos += 1
        chars: list[str] = []
        escapes = {
            "'": "'",
            '"': '"',
            "\\": "\\",
            "/": "/",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "v": "\v",
            "0": "\0",
        }
        while self.pos < len(self.source):
            char = self.source[self.pos]
            self.pos += 1
            if char == quote:
                return "".join(chars)
            if char in {"\n", "\r"} and quote != "`":
                raise self._error("unescaped newline in string")
            if char != "\\":
                chars.append(char)
                continue
            if self.pos >= len(self.source):
                raise self._error("unterminated string escape")
            escaped = self.source[self.pos]
            self.pos += 1
            if escaped in escapes:
                chars.append(escapes[escaped])
            elif escaped == "u":
                chars.append(self._unicode_escape(4))
            elif escaped == "x":
                chars.append(self._unicode_escape(2))
            elif escaped in {"\n", "\r"}:
                if escaped == "\r" and self._consume("\n"):
                    pass
            else:
                chars.append(escaped)
        raise self._error("unterminated string")

    def _unicode_escape(self, length: int) -> str:
        raw = self.source[self.pos : self.pos + length]
        if len(raw) != length or not re.fullmatch(
            rf"[0-9A-Fa-f]{{{length}}}", raw
        ):
            raise self._error("invalid hexadecimal string escape")
        self.pos += length
        return chr(int(raw, 16))

    def _consume(self, token: str) -> bool:
        if self.source.startswith(token, self.pos):
            self.pos += len(token)
            return True
        return False


def _mask_non_code(source: str) -> str:
    chars = list(source)
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block":
            chars[index] = " "
            if char == "*" and next_char == "/":
                chars[index + 1] = " "
                index += 1
                state = "code"
        elif state == "string":
            if char != "\n":
                chars[index] = " "
            if char == "\\":
                if index + 1 < len(source):
                    chars[index + 1] = " "
                    index += 1
            elif char == quote:
                state = "code"
        elif char == "/" and next_char == "/":
            chars[index] = chars[index + 1] = " "
            index += 1
            state = "line"
        elif char == "/" and next_char == "*":
            chars[index] = chars[index + 1] = " "
            index += 1
            state = "block"
        elif char in {"'", '"', "`"}:
            chars[index] = " "
            quote = char
            state = "string"
        index += 1
    return "".join(chars)


def _extract_inline_scripts(html: str) -> list[str]:
    return [
        match.group(2)
        for match in re.finditer(
            r"<script([^>]*)>([\s\S]*?)</script>", html, re.IGNORECASE
        )
        if not re.search(r"\bsrc\s*=", match.group(1), re.IGNORECASE)
    ]


def _extract_constant(html: str, name: str) -> Any:
    declaration = re.compile(
        rf"\bconst\s+{re.escape(name)}\s*="
    )
    for script in _extract_inline_scripts(html):
        masked = _mask_non_code(script)
        match = declaration.search(masked)
        if not match:
            continue
        parser = JSLiteralParser(script, match.end())
        value = parser.parse()
        if parser.pos >= len(script) or script[parser.pos] != ";":
            raise LiteralParseError(
                f"const {name} must contain one semicolon-terminated data literal"
            )
        return value
    raise LiteralParseError(f"const {name} declaration was not found")


def _parse_runtime_path(path: str) -> tuple[str, list[tuple[str, Any]]]:
    root_match = IDENTIFIER_RE.match(path)
    if not root_match:
        raise RuntimePathError("path must start with a constant identifier")
    root = root_match.group(0)
    pos = root_match.end()
    segments: list[tuple[str, Any]] = []
    while pos < len(path):
        if path[pos] == ".":
            match = IDENTIFIER_RE.match(path, pos + 1)
            if not match:
                raise RuntimePathError(
                    f"invalid property segment at offset {pos}"
                )
            segments.append(("property", match.group(0)))
            pos = match.end()
            continue
        if path[pos] == "[":
            end = path.find("]", pos + 1)
            if end < 0:
                raise RuntimePathError(
                    f"unterminated bracket segment at offset {pos}"
                )
            content = path[pos + 1 : end].strip()
            if re.fullmatch(r"\d+", content):
                segments.append(("index", int(content)))
            elif "=" in content:
                key, value = content.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not IDENTIFIER_RE.fullmatch(key) or not value:
                    raise RuntimePathError(
                        f"invalid array selector [{content}]"
                    )
                if (
                    len(value) >= 2
                    and value[0] == value[-1]
                    and value[0] in {"'", '"'}
                ):
                    value = JSLiteralParser(value).parse()
                segments.append(("select", (key, str(value))))
            else:
                raise RuntimePathError(
                    f"brackets require an index or key=value selector: [{content}]"
                )
            pos = end + 1
            continue
        raise RuntimePathError(
            f"unexpected character {path[pos]!r} at offset {pos}"
        )
    return root, segments


def _resolve_runtime_path(root_value: Any, segments: list[tuple[str, Any]]) -> Any:
    value = root_value
    traversed = "$"
    for kind, parameter in segments:
        if kind == "property":
            if not isinstance(value, dict) or parameter not in value:
                raise RuntimePathError(
                    f"{traversed} has no property {parameter!r}"
                )
            value = value[parameter]
            traversed += f".{parameter}"
        elif kind == "index":
            if not isinstance(value, list) or parameter >= len(value):
                raise RuntimePathError(
                    f"{traversed} has no array index {parameter}"
                )
            value = value[parameter]
            traversed += f"[{parameter}]"
        else:
            key, expected = parameter
            if not isinstance(value, list):
                raise RuntimePathError(
                    f"{traversed} is not an array for [{key}={expected}]"
                )
            matches = [
                item
                for item in value
                if isinstance(item, dict)
                and key in item
                and str(_json_value(item[key])) == expected
            ]
            if len(matches) != 1:
                raise RuntimePathError(
                    f"{traversed}[{key}={expected}] matched {len(matches)} items"
                )
            value = matches[0]
            traversed += f"[{key}={expected}]"
    return value


def _transform_value(value: Any, spec: Any) -> Any:
    if not isinstance(spec, dict):
        raise ValueError("transform must be an object")
    op = spec.get("op")
    if op not in TRANSFORMS:
        raise ValueError(
            f"unsupported transform {op!r}; allowed: {sorted(TRANSFORMS)}"
        )
    if op == "identity":
        return value
    if op == "multiply":
        number = _as_decimal(value)
        factor = _as_decimal(spec.get("factor"))
        if number is None or factor is None:
            raise ValueError(
                "multiply requires numeric runtime value and factor"
            )
        return number * factor
    if op == "sum":
        if not isinstance(value, list) or len(value) < 2:
            raise ValueError("sum requires at least two runtime paths")
        numbers = [_as_decimal(item) for item in value]
        if any(item is None or not item.is_finite() for item in numbers):
            raise ValueError("sum inputs must be finite numbers")
        return sum(numbers, Decimal(0))
    if op == "joinRange":
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError("joinRange requires a two-item array")
        numbers = [_as_decimal(item) for item in value]
        if any(item is None or not item.is_finite() for item in numbers):
            raise ValueError("joinRange values must be finite numbers")
        separator = spec.get("separator", "-")
        if not isinstance(separator, str) or not separator:
            raise ValueError("joinRange separator must be a non-empty string")
        return separator.join(_canonical_decimal(item) for item in numbers)
    if op == "extractRange":
        if not isinstance(value, str):
            raise ValueError("extractRange requires a string")
        match = RANGE_RE.search(value.replace(",", ""))
        if not match:
            raise ValueError("extractRange found no numeric range")
        separator = spec.get("separator", "-")
        if not isinstance(separator, str) or not separator:
            raise ValueError("extractRange separator must be a non-empty string")
        numbers = [Decimal(match.group(1)), Decimal(match.group(2))]
        return separator.join(_canonical_decimal(item) for item in numbers)
    if not isinstance(value, list) or not value:
        raise ValueError("serializeBrackets requires a non-empty array")
    infinity_label = spec.get("infinityLabel", "above")
    if not isinstance(infinity_label, str) or not infinity_label:
        raise ValueError(
            "serializeBrackets infinityLabel must be a non-empty string"
        )
    rows: list[str] = []
    preserve_rate_scale = spec.get("preserveRateScale", False)
    if not isinstance(preserve_rate_scale, bool):
        raise ValueError(
            "serializeBrackets preserveRateScale must be boolean"
        )
    for index, row in enumerate(value):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError(
                f"serializeBrackets row {index} must be [threshold, rate]"
            )
        threshold = _as_decimal(row[0])
        rate = _as_decimal(row[1])
        if threshold is None or rate is None or not rate.is_finite():
            raise ValueError(
                f"serializeBrackets row {index} contains a non-finite rate"
            )
        if threshold.is_infinite() and threshold > 0 and index == len(value) - 1:
            threshold_text = infinity_label
        elif threshold.is_finite():
            threshold_text = _canonical_decimal(threshold)
        else:
            raise ValueError(
                "only the final positive Infinity threshold is supported"
            )
        rate_text = (
            format(rate, "f")
            if preserve_rate_scale
            else _canonical_decimal(rate)
        )
        rows.append(f"{threshold_text}@{rate_text}")
    return ";".join(rows)


def _boundary_values(value: Any) -> list[str]:
    if isinstance(value, Decimal):
        return [_canonical_decimal(value)] if value.is_finite() else []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(_boundary_values(item))
        return list(dict.fromkeys(result))
    if isinstance(value, str):
        range_match = RANGE_RE.fullmatch(value.strip())
        if range_match:
            return [
                _canonical_decimal(Decimal(range_match.group(1))),
                _canonical_decimal(Decimal(range_match.group(2))),
            ]
        numbers = [
            _canonical_decimal(Decimal(match.group(0)))
            for match in re.finditer(r"[+-]?\d+(?:\.\d+)?", value)
        ]
        return list(dict.fromkeys(numbers))
    return []


def _load_json(
    path: Path, report: RuntimeReport, *, kind: str
) -> Any | None:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_float=Decimal,
            parse_int=Decimal,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        report.issues.append(
            RuntimeIssue(
                f"INVALID_{kind.upper()}",
                "<registry>",
                "<all>",
                str(path),
                str(exc),
                "valid UTF-8 JSON",
                f"Repair the {kind} JSON file.",
            )
        )
        return None


def _issue(
    report: RuntimeReport,
    code: str,
    binding: dict[str, Any] | None,
    actual: Any,
    expected: Any,
    fix: str,
    *,
    claim_id: str | None = None,
    edition: str | None = None,
    runtime_path: str | None = None,
) -> None:
    report.issues.append(
        RuntimeIssue(
            code,
            claim_id
            if claim_id is not None
            else str((binding or {}).get("claimId", "<binding>")),
            edition
            if edition is not None
            else str((binding or {}).get("edition", "<unknown>")),
            runtime_path
            if runtime_path is not None
            else str((binding or {}).get("runtimePath", "<unknown>")),
            actual,
            expected,
            fix,
        )
    )


def verify_runtime_parity(
    root: Path | str,
    *,
    claims_path: Path | str = "data/claims.json",
    bindings_path: Path | str,
) -> RuntimeReport:
    report = RuntimeReport()
    root_path = Path(root).resolve()
    claims_file = Path(claims_path)
    if not claims_file.is_absolute():
        claims_file = root_path / claims_file
    bindings_file = Path(bindings_path)
    if not bindings_file.is_absolute():
        bindings_file = root_path / bindings_file

    claims_data = _load_json(claims_file, report, kind="claims")
    bindings_data = _load_json(bindings_file, report, kind="bindings")
    if claims_data is None or bindings_data is None:
        return report
    if not isinstance(claims_data, dict) or not isinstance(
        claims_data.get("claims"), list
    ):
        _issue(
            report,
            "INVALID_CLAIMS",
            None,
            claims_data,
            "{claims: []}",
            "Use a claim registry with a claims array.",
            runtime_path=str(claims_file),
        )
        return report
    if (
        not isinstance(bindings_data, dict)
        or bindings_data.get("schemaVersion") != SCHEMA_VERSION
        or not isinstance(bindings_data.get("bindings"), list)
    ):
        _issue(
            report,
            "INVALID_BINDINGS",
            None,
            bindings_data,
            "{schemaVersion: 1, bindings: []}",
            "Use the documented runtime-binding root schema.",
            runtime_path=str(bindings_file),
        )
        return report

    claims: dict[str, dict[str, Any]] = {}
    for index, claim in enumerate(claims_data["claims"]):
        if not isinstance(claim, dict) or not isinstance(claim.get("id"), str):
            _issue(
                report,
                "INVALID_CLAIM",
                None,
                claim,
                "claim object with string id",
                "Repair the claim registry entry.",
                claim_id=f"<claim {index + 1}>",
                runtime_path=str(claims_file),
            )
            continue
        claim_id = claim["id"]
        if claim_id in claims:
            _issue(
                report,
                "DUPLICATE_CLAIM",
                None,
                claim_id,
                "unique claim id",
                "Remove the duplicate claim.",
                claim_id=claim_id,
                runtime_path=str(claims_file),
            )
            continue
        claims[claim_id] = _normalize_json_value(claim)

    raw_scope = bindings_data.get("claimScope")
    if raw_scope is None:
        raw_scope = list(
            dict.fromkeys(
                binding.get("claimId")
                for binding in bindings_data["bindings"]
                if isinstance(binding, dict)
                and isinstance(binding.get("claimId"), str)
                and binding.get("claimId")
            )
        )
    elif not isinstance(raw_scope, list):
        _issue(
            report,
            "INVALID_SCOPE",
            None,
            raw_scope,
            "optional array of claim ids",
            "Remove claimScope or replace it with an array.",
            runtime_path=str(bindings_file),
        )
        raw_scope = []

    scope: list[str] = []
    seen_scope: set[str] = set()
    for index, claim_id in enumerate(raw_scope):
        if not isinstance(claim_id, str) or not claim_id:
            _issue(
                report,
                "INVALID_SCOPE",
                None,
                claim_id,
                "non-empty claim id",
                "Replace the scope item with a claim id.",
                claim_id=f"<scope {index + 1}>",
                runtime_path=str(bindings_file),
            )
            continue
        if claim_id in seen_scope:
            _issue(
                report,
                "DUPLICATE_SCOPE",
                None,
                claim_id,
                "unique claimScope entry",
                "Remove the duplicate scope item.",
                claim_id=claim_id,
                runtime_path=str(bindings_file),
            )
            continue
        seen_scope.add(claim_id)
        scope.append(claim_id)
        if claim_id not in claims:
            _issue(
                report,
                "UNKNOWN_SCOPE_CLAIM",
                None,
                "missing from claim registry",
                "existing claim",
                "Remove the scope id or add the claim before binding it.",
                claim_id=claim_id,
                runtime_path=str(bindings_file),
            )

    valid_bindings: list[dict[str, Any]] = []
    seen_claim_binding: set[tuple[str, str]] = set()
    seen_runtime_binding: set[tuple[str, str, str]] = set()
    bound_claims: set[str] = set()
    for index, raw_binding in enumerate(bindings_data["bindings"]):
        if not isinstance(raw_binding, dict):
            _issue(
                report,
                "INVALID_BINDING",
                None,
                raw_binding,
                "binding object",
                "Replace the entry with a binding object.",
                claim_id=f"<binding {index + 1}>",
                runtime_path=str(bindings_file),
            )
            continue
        binding = _normalize_json_value(raw_binding)
        invalid = False
        for field_name in REQUIRED_BINDING_FIELDS:
            value = binding.get(field_name)
            if field_name == "runtimePath":
                valid_runtime_path = (
                    isinstance(value, str)
                    and bool(value)
                    or isinstance(value, list)
                    and len(value) >= 2
                    and all(isinstance(item, str) and item for item in value)
                )
                if valid_runtime_path:
                    continue
            elif field_name == "transform":
                if isinstance(value, dict) and isinstance(
                    value.get("op"), str
                ):
                    continue
            elif isinstance(value, str) and value:
                continue
            invalid = True
            _issue(
                report,
                "INVALID_BINDING",
                binding,
                value,
                f"valid field {field_name}",
                f"Set binding.{field_name}.",
                runtime_path=str(binding.get("runtimePath", bindings_file)),
            )
        if invalid:
            continue
        if binding["type"] not in VALUE_TYPES:
            _issue(
                report,
                "INVALID_BINDING",
                binding,
                binding["type"],
                sorted(VALUE_TYPES),
                "Use a supported type.",
            )
            continue
        transform_op = binding["transform"].get("op")
        if transform_op not in TRANSFORMS:
            _issue(
                report,
                "INVALID_BINDING",
                binding,
                transform_op,
                sorted(TRANSFORMS),
                "Use a supported transform op.",
            )
            continue
        provenance = binding.get("provenance")
        if provenance is not None:
            if not isinstance(provenance, dict):
                _issue(
                    report,
                    "INVALID_PROVENANCE",
                    binding,
                    provenance,
                    {
                        "sourcePath": "path or path array",
                        "dates": "non-empty date binding array",
                    },
                    "Replace provenance with the documented object or remove it.",
                )
                continue
            missing_provenance_fields = sorted(
                PROVENANCE_FIELDS - set(provenance)
            )
            if missing_provenance_fields:
                _issue(
                    report,
                    "ORPHAN_PROVENANCE",
                    binding,
                    {
                        "missing": missing_provenance_fields,
                        "provenance": provenance,
                    },
                    sorted(PROVENANCE_FIELDS),
                    "Declare sourcePath and dates together, or remove provenance.",
                )
                continue
            unsupported_provenance_fields = sorted(
                set(provenance) - PROVENANCE_FIELDS
            )
            if unsupported_provenance_fields:
                _issue(
                    report,
                    "INVALID_PROVENANCE",
                    binding,
                    unsupported_provenance_fields,
                    sorted(PROVENANCE_FIELDS),
                    "Remove unsupported provenance fields.",
                )
                continue
            if not _is_provenance_path_spec(provenance["sourcePath"]):
                _issue(
                    report,
                    "INVALID_PROVENANCE",
                    binding,
                    provenance["sourcePath"],
                    "one path string or an array of at least two path strings",
                    "Correct provenance.sourcePath; arrays are for composite bindings only.",
                )
                continue
            dates = provenance["dates"]
            if not isinstance(dates, list) or not dates:
                _issue(
                    report,
                    "ORPHAN_PROVENANCE",
                    binding,
                    dates,
                    "one or more provenance date bindings",
                    "Add at least one dates entry or remove provenance.",
                )
                continue
            seen_claim_date_fields: set[str] = set()
            invalid_dates = False
            for date_index, date_binding in enumerate(dates):
                if not isinstance(date_binding, dict):
                    _issue(
                        report,
                        "INVALID_PROVENANCE",
                        binding,
                        date_binding,
                        {
                            "runtimePath": "path or path array",
                            "claimField": sorted(CLAIM_DATE_FIELDS),
                        },
                        f"Replace provenance.dates[{date_index}] with a date binding object.",
                    )
                    invalid_dates = True
                    continue
                missing_date_fields = sorted(
                    PROVENANCE_DATE_FIELDS - set(date_binding)
                )
                extra_date_fields = sorted(
                    set(date_binding) - PROVENANCE_DATE_FIELDS
                )
                if missing_date_fields:
                    _issue(
                        report,
                        "ORPHAN_PROVENANCE",
                        binding,
                        {"missing": missing_date_fields, "date": date_binding},
                        sorted(PROVENANCE_DATE_FIELDS),
                        f"Complete provenance.dates[{date_index}] or remove it.",
                    )
                    invalid_dates = True
                    continue
                if extra_date_fields:
                    _issue(
                        report,
                        "INVALID_PROVENANCE",
                        binding,
                        extra_date_fields,
                        sorted(PROVENANCE_DATE_FIELDS),
                        f"Remove unsupported fields from provenance.dates[{date_index}].",
                    )
                    invalid_dates = True
                    continue
                runtime_path_spec = date_binding["runtimePath"]
                if not _is_provenance_path_spec(runtime_path_spec):
                    _issue(
                        report,
                        "INVALID_PROVENANCE",
                        binding,
                        runtime_path_spec,
                        "one path string or an array of at least two path strings",
                        f"Correct provenance.dates[{date_index}].runtimePath.",
                    )
                    invalid_dates = True
                claim_field = date_binding["claimField"]
                if claim_field not in CLAIM_DATE_FIELDS:
                    _issue(
                        report,
                        "UNSUPPORTED_PROVENANCE_FIELD",
                        binding,
                        claim_field,
                        sorted(CLAIM_DATE_FIELDS),
                        "Use verifiedAt, effectiveFrom, effectiveTo, or currentAsOf.",
                        runtime_path=str(runtime_path_spec),
                    )
                    invalid_dates = True
                elif claim_field in seen_claim_date_fields:
                    _issue(
                        report,
                        "DUPLICATE_PROVENANCE_DATE",
                        binding,
                        claim_field,
                        "one date mapping per claim field",
                        f"Remove the duplicate provenance date for {claim_field}.",
                        runtime_path=str(runtime_path_spec),
                    )
                    invalid_dates = True
                else:
                    seen_claim_date_fields.add(claim_field)
            if invalid_dates:
                continue
        if isinstance(binding["runtimePath"], list) != (transform_op == "sum"):
            _issue(
                report,
                "INVALID_BINDING",
                binding,
                binding["runtimePath"],
                (
                    "array of runtime paths for sum"
                    if transform_op == "sum"
                    else "single runtime path string"
                ),
                "Use a path array only with the sum transform.",
            )
            continue
        claim_key = (binding["claimId"], binding["edition"])
        runtime_key = (
            binding["edition"],
            binding["page"],
            (
                tuple(binding["runtimePath"])
                if isinstance(binding["runtimePath"], list)
                else binding["runtimePath"]
            ),
        )
        if claim_key in seen_claim_binding:
            _issue(
                report,
                "DUPLICATE_BINDING",
                binding,
                claim_key,
                "one binding per claim and edition",
                "Remove the duplicate claim binding.",
            )
            continue
        if runtime_key in seen_runtime_binding:
            _issue(
                report,
                "DUPLICATE_BINDING",
                binding,
                runtime_key,
                "one claim per runtime target",
                "Remove or consolidate the duplicate runtime binding.",
            )
            continue
        seen_claim_binding.add(claim_key)
        seen_runtime_binding.add(runtime_key)
        bound_claims.add(binding["claimId"])
        if binding["claimId"] not in seen_scope:
            _issue(
                report,
                "UNSCOPED_BINDING",
                binding,
                binding["claimId"],
                "claim id listed in claimScope",
                "Add the claim to claimScope or remove the binding.",
            )
        if binding["claimId"] not in claims:
            _issue(
                report,
                "ORPHAN_BINDING",
                binding,
                "claim not found",
                "existing claim id",
                "Remove the binding or add the claim first.",
            )
            continue
        valid_bindings.append(binding)

    for claim_id in scope:
        if claim_id in claims and claim_id not in bound_claims:
            _issue(
                report,
                "ORPHAN_CLAIM",
                None,
                "no runtime binding",
                "exactly one binding",
                "Add a binding or remove the claim from claimScope.",
                claim_id=claim_id,
                runtime_path="<unbound>",
            )

    page_cache: dict[str, str] = {}
    constant_cache: dict[tuple[str, str], Any] = {}
    actual_by_claim: dict[str, tuple[dict[str, Any], Any]] = {}

    def extract_runtime_value(page: str, runtime_path: str) -> Any:
        if page not in page_cache:
            page_path = (root_path / page).resolve()
            page_cache[page] = page_path.read_text(encoding="utf-8")
        root_name, segments = _parse_runtime_path(runtime_path)
        cache_key = (page, root_name)
        if cache_key not in constant_cache:
            constant_cache[cache_key] = _extract_constant(
                page_cache[page], root_name
            )
        return _resolve_runtime_path(constant_cache[cache_key], segments)

    for binding in valid_bindings:
        claim = claims[binding["claimId"]]
        edition = binding["edition"]
        meta = EDITION_META.get(edition)
        if meta is None:
            _issue(
                report,
                "EDITION_MISMATCH",
                binding,
                edition,
                sorted(EDITION_META),
                "Use one of the supported edition ids.",
            )
            continue
        if binding["page"] != meta["page"]:
            _issue(
                report,
                "EDITION_MISMATCH",
                binding,
                binding["page"],
                meta["page"],
                "Use the canonical page for this edition.",
            )
            continue
        if (
            claim.get("country") != meta["country"]
            or claim.get("locale") != meta["locale"]
            or binding["page"] not in claim.get("pages", [])
        ):
            _issue(
                report,
                "EDITION_MISMATCH",
                binding,
                {
                    "country": claim.get("country"),
                    "locale": claim.get("locale"),
                    "pages": claim.get("pages"),
                },
                {
                    "country": meta["country"],
                    "locale": meta["locale"],
                    "page": binding["page"],
                },
                "Correct the binding edition/page or the claim ownership.",
            )
            continue
        if claim.get("unit") != binding["unit"]:
            _issue(
                report,
                "UNIT_MISMATCH",
                binding,
                binding["unit"],
                claim.get("unit"),
                "Set unit to the exact claim unit.",
            )
            continue
        if _value_type(claim.get("value")) != binding["type"]:
            _issue(
                report,
                "TYPE_MISMATCH",
                binding,
                _value_type(claim.get("value")),
                binding["type"],
                "Correct type or migrate the claim value type.",
            )
            continue

        page = binding["page"]
        page_path = (root_path / page).resolve()
        try:
            page_path.relative_to(root_path)
        except ValueError:
            _issue(
                report,
                "BAD_PAGE",
                binding,
                str(page_path),
                "repository-relative page",
                "Remove absolute or parent path components.",
            )
            continue
        runtime_paths = (
            binding["runtimePath"]
            if isinstance(binding["runtimePath"], list)
            else [binding["runtimePath"]]
        )
        try:
            extracted_values: list[Any] = []
            for runtime_path in runtime_paths:
                extracted_values.append(
                    extract_runtime_value(page, runtime_path)
                )
            raw_value = (
                extracted_values
                if isinstance(binding["runtimePath"], list)
                else extracted_values[0]
            )
        except RuntimePathError as exc:
            _issue(
                report,
                "BAD_RUNTIME_PATH",
                binding,
                str(exc),
                "valid constant/property/index path",
                "Correct runtimePath using the documented path grammar.",
            )
            continue
        except (OSError, UnicodeError, LiteralParseError) as exc:
            _issue(
                report,
                "EXTRACTION_FAILED",
                binding,
                str(exc),
                "extractable data-literal runtime value",
                "Correct the page/path or move the value into a supported literal constant.",
            )
            continue

        transform = binding.get("transform")
        try:
            transformed = _transform_value(raw_value, transform)
        except (ValueError, InvalidOperation) as exc:
            _issue(
                report,
                "TRANSFORM_FAILED",
                binding,
                str(exc),
                "successful allowlisted transform",
                "Correct the transform op/arguments or runtime value shape.",
            )
            continue
        non_finite = _non_finite_path(transformed)
        if non_finite:
            _issue(
                report,
                "NON_FINITE_RUNTIME",
                binding,
                {"path": non_finite, "value": transformed},
                "finite runtime value",
                "Replace NaN/Infinity with a finite constant or an approved final bracket sentinel.",
            )
            continue
        if _value_type(transformed) != binding["type"]:
            _issue(
                report,
                "TYPE_MISMATCH",
                binding,
                _value_type(transformed),
                binding["type"],
                "Correct type or add an allowlisted transform.",
            )
            continue
        if transformed != claim.get("value"):
            _issue(
                report,
                "VALUE_MISMATCH",
                binding,
                transformed,
                claim.get("value"),
                "Update the runtime constant or claim through the factual review workflow.",
            )
            continue

        provenance = binding.get("provenance")
        provenance_ok = True
        if provenance is not None:
            claim_source = claim.get("sourceUrl")
            expected_source: str | None = None
            try:
                expected_source = _normalized_source_url(claim_source)
            except ProvenanceValueError as exc:
                provenance_ok = False
                _issue(
                    report,
                    "MISSING_CLAIM_PROVENANCE",
                    binding,
                    {"value": claim_source, "error": str(exc)},
                    "claim sourceUrl containing an absolute http(s) URL",
                    "Repair claim.sourceUrl before enabling strict provenance.",
                    runtime_path=str(provenance["sourcePath"]),
                )
            for source_path in _provenance_paths(
                provenance["sourcePath"]
            ):
                try:
                    runtime_source = extract_runtime_value(page, source_path)
                except RuntimePathError as exc:
                    provenance_ok = False
                    _issue(
                        report,
                        "BAD_PROVENANCE_PATH",
                        binding,
                        str(exc),
                        "valid constant/property/index provenance path",
                        "Correct provenance.sourcePath.",
                        runtime_path=source_path,
                    )
                    continue
                except (OSError, UnicodeError, LiteralParseError) as exc:
                    provenance_ok = False
                    _issue(
                        report,
                        "PROVENANCE_EXTRACTION_FAILED",
                        binding,
                        str(exc),
                        "extractable data-literal provenance value",
                        "Move provenance into a supported literal constant and correct its path.",
                        runtime_path=source_path,
                    )
                    continue
                try:
                    actual_source = _normalized_source_url(runtime_source)
                except ProvenanceValueError as exc:
                    provenance_ok = False
                    _issue(
                        report,
                        "INVALID_PROVENANCE_URL",
                        binding,
                        {"value": runtime_source, "error": str(exc)},
                        "absolute http(s) source URL",
                        "Set the runtime source field to the claim's reviewed sourceUrl.",
                        runtime_path=source_path,
                    )
                    continue
                if (
                    expected_source is not None
                    and actual_source != expected_source
                ):
                    provenance_ok = False
                    _issue(
                        report,
                        "PROVENANCE_URL_MISMATCH",
                        binding,
                        runtime_source,
                        claim_source,
                        "Align every runtime source URL with claim.sourceUrl through factual review.",
                        runtime_path=source_path,
                    )
                elif expected_source is not None:
                    report.checked_provenance_sources += 1

            for date_binding in provenance["dates"]:
                claim_date_field = date_binding["claimField"]
                claim_date = claim.get(claim_date_field)
                try:
                    expected_date = _iso_date(claim_date)
                except ProvenanceValueError as exc:
                    provenance_ok = False
                    _issue(
                        report,
                        "MISSING_CLAIM_PROVENANCE",
                        binding,
                        {
                            "field": claim_date_field,
                            "value": claim_date,
                            "error": str(exc),
                        },
                        f"claim.{claim_date_field} as a real ISO YYYY-MM-DD date",
                        f"Repair claim.{claim_date_field} or remove its provenance date mapping.",
                        runtime_path=str(date_binding["runtimePath"]),
                    )
                    expected_date = None
                for date_path in _provenance_paths(
                    date_binding["runtimePath"]
                ):
                    try:
                        runtime_date = extract_runtime_value(page, date_path)
                    except RuntimePathError as exc:
                        provenance_ok = False
                        _issue(
                            report,
                            "BAD_PROVENANCE_PATH",
                            binding,
                            str(exc),
                            "valid constant/property/index provenance path",
                            "Correct the provenance date runtimePath.",
                            runtime_path=date_path,
                        )
                        continue
                    except (OSError, UnicodeError, LiteralParseError) as exc:
                        provenance_ok = False
                        _issue(
                            report,
                            "PROVENANCE_EXTRACTION_FAILED",
                            binding,
                            str(exc),
                            "extractable data-literal provenance value",
                            "Move provenance into a supported literal constant and correct its path.",
                            runtime_path=date_path,
                        )
                        continue
                    try:
                        actual_date = _iso_date(runtime_date)
                    except ProvenanceValueError as exc:
                        provenance_ok = False
                        _issue(
                            report,
                            "INVALID_PROVENANCE_DATE",
                            binding,
                            {
                                "value": runtime_date,
                                "error": str(exc),
                            },
                            "real ISO YYYY-MM-DD runtime date",
                            "Set the runtime provenance field to a reviewed literal date.",
                            runtime_path=date_path,
                        )
                        continue
                    if (
                        expected_date is not None
                        and actual_date != expected_date
                    ):
                        provenance_ok = False
                        _issue(
                            report,
                            "PROVENANCE_DATE_MISMATCH",
                            binding,
                            runtime_date,
                            claim_date,
                            f"Align this runtime date with claim.{claim_date_field}.",
                            runtime_path=date_path,
                        )
                    elif expected_date is not None:
                        report.checked_provenance_dates += 1
        if not provenance_ok:
            continue

        boundary = binding.get("boundary")
        if boundary is not None:
            if (
                not isinstance(boundary, dict)
                or boundary.get("kind") not in BOUNDARY_KINDS
            ):
                _issue(
                    report,
                    "INVALID_BOUNDARY",
                    binding,
                    boundary,
                    {"kind": sorted(BOUNDARY_KINDS)},
                    "Use a supported boundary kind.",
                )
                continue
            values = _boundary_values(transformed)
            if not values:
                _issue(
                    report,
                    "INVALID_BOUNDARY",
                    binding,
                    transformed,
                    "value containing finite numeric boundaries",
                    "Remove boundary metadata or use a numeric/range value.",
                )
                continue
            report.boundary_cases.append(
                {
                    "claimId": binding["claimId"],
                    "edition": edition,
                    "kind": boundary["kind"],
                    "unit": binding["unit"],
                    "values": values,
                }
            )
        report.checked_bindings += 1
        actual_by_claim[binding["claimId"]] = (binding, transformed)

    parity_keys = bindings_data.get("parityKeys", [])
    if not isinstance(parity_keys, list) or any(
        not isinstance(key, str) or not key for key in parity_keys
    ):
        _issue(
            report,
            "INVALID_BINDINGS",
            None,
            parity_keys,
            "array of non-empty parity keys",
            "Repair bindings.parityKeys.",
            runtime_path=str(bindings_file),
        )
        parity_keys = []
    for parity_key in dict.fromkeys(parity_keys):
        members = [
            claim
            for claim in claims.values()
            if claim.get("parityKey") == parity_key
        ]
        if len(members) < 2:
            _issue(
                report,
                "ORPHAN_PARITY_KEY",
                None,
                [claim.get("id") for claim in members],
                "at least two claims",
                "Remove the parity key or add its counterpart claims.",
                claim_id=parity_key,
                edition="nz/ja",
                runtime_path=f"<parity:{parity_key}>",
            )
            continue
        missing = [
            claim["id"]
            for claim in members
            if claim["id"] not in actual_by_claim
        ]
        if missing:
            _issue(
                report,
                "ORPHAN_PARITY_BINDING",
                None,
                missing,
                "runtime binding for every parity member",
                "Add all parity members to claimScope and bindings.",
                claim_id=parity_key,
                edition="nz/ja",
                runtime_path=f"<parity:{parity_key}>",
            )
            continue
        baseline_claim = members[0]
        baseline = actual_by_claim[baseline_claim["id"]][1]
        baseline_unit = baseline_claim.get("unit")
        for member in members[1:]:
            actual = actual_by_claim[member["id"]][1]
            if actual != baseline or member.get("unit") != baseline_unit:
                _issue(
                    report,
                    "RUNTIME_PARITY_MISMATCH",
                    actual_by_claim[member["id"]][0],
                    {"value": actual, "unit": member.get("unit")},
                    {"value": baseline, "unit": baseline_unit},
                    "Align both runtime constants with the parity-linked claims.",
                    claim_id=parity_key,
                    edition="nz/ja",
                    runtime_path=f"<parity:{parity_key}>",
                )

    production_bindings_file = (root_path / "data/runtime-bindings.json").resolve()
    public_audit = (
        claims_data.get("audit", {}).get("runtimeBindings")
        if bindings_file.resolve() == production_bindings_file
        else None
    )
    if public_audit is not None:
        expected_audit = {
            "claimCount": len(
                {
                    binding.get("claimId")
                    for binding in bindings_data["bindings"]
                    if isinstance(binding, dict)
                    and isinstance(binding.get("claimId"), str)
                }
            ),
            "bindingCount": len(bindings_data["bindings"]),
            "boundarySetCount": len(report.boundary_cases),
        }
        if any(
            isinstance(binding, dict) and "provenance" in binding
            for binding in bindings_data["bindings"]
        ):
            expected_audit.update(
                {
                    "provenanceSourceCheckCount": (
                        report.checked_provenance_sources
                    ),
                    "provenanceDateCheckCount": (
                        report.checked_provenance_dates
                    ),
                }
            )
        actual_audit = _normalize_json_value(public_audit)
        normalized_expected = _normalize_json_value(expected_audit)
        audit_subset = (
            {
                key: actual_audit.get(key)
                for key in normalized_expected
            }
            if isinstance(actual_audit, dict)
            else actual_audit
        )
        if audit_subset != normalized_expected:
            _issue(
                report,
                "PUBLIC_AUDIT_MISMATCH",
                None,
                audit_subset,
                normalized_expected,
                "Update claims.audit.runtimeBindings from the verified production binding registry.",
                claim_id="<runtime-audit>",
                edition="<all>",
                runtime_path=str(claims_file),
            )

    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare claim values with safely parsed inline runtime constants."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    parser.add_argument(
        "--claims",
        default="data/claims.json",
        help="claim registry path (default: data/claims.json)",
    )
    parser.add_argument(
        "--bindings",
        required=True,
        help="runtime binding registry; explicit input is required",
    )
    parser.add_argument(
        "--dump-boundaries",
        action="store_true",
        help="print generated boundary cases as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = verify_runtime_parity(
        args.root,
        claims_path=args.claims,
        bindings_path=args.bindings,
    )
    if report.issues:
        print(
            f"Runtime parity verification failed with "
            f"{len(report.issues)} error(s):",
            file=sys.stderr,
        )
        for issue in report.issues:
            print(issue.render(), file=sys.stderr)
        return 1
    print(
        f"Runtime parity verification passed: "
        f"{report.checked_bindings} binding(s), "
        f"{len(report.boundary_cases)} boundary set(s), "
        f"{report.checked_provenance_sources} provenance source check(s), "
        f"{report.checked_provenance_dates} provenance date check(s)."
    )
    if args.dump_boundaries:
        print(
            json.dumps(
                {
                    "schemaVersion": SCHEMA_VERSION,
                    "boundaries": report.boundary_cases,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
