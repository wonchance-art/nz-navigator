#!/usr/bin/env python3
"""Detect sensitive numeric claims that are neither marked nor exempted."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import textwrap
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


DEFAULT_PAGES = ("nz/index.html", "ja/index.html", "ca/index.html", "au/index.html")
DEFAULT_EXEMPTIONS = "data/claim-coverage-exemptions.json"
DEFAULT_CLAIM_REGISTRY = "data/claims.json"
EXEMPTION_FIELDS = ("selector", "fingerprint", "reason", "owner", "expiresAt")
SEMANTIC_TAGS = frozenset(
    {"p", "li", "tr", "label", "summary", "h1", "h2", "h3", "h4", "h5", "h6"}
)
IGNORED_TAGS = frozenset({"style", "script", "svg", "template", "noscript"})
IGNORED_CONTEXT = re.compile(
    r"(?:scenario|changeline|flight|calendar|season(?:al)?-map|city-map|diagnose)",
    re.IGNORECASE,
)
VISA_IDENTIFIERS = frozenset(
    {
        "186",
        "189",
        "190",
        "191",
        "417",
        "462",
        "482",
        "485",
        "491",
        "500",
        "820",
    }
)
NUMBER_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?(?:[kKmM]\b)?"
    r"(?![A-Za-z0-9_])"
)
DATE_SPAN_RE = re.compile(
    r"\b20\d{2}[-/]\d{1,2}(?:[-/]\d{1,2})?\b|"
    r"\b\d{1,2}\s*월\s*\d{1,2}\s*일\b"
)
TIME_UNIT_RE = re.compile(
    r"(?:년|개월|주|일|시간|歳|年|ヶ月|か月|週間|日|時間|"
    r"years?|months?|weeks?|days?|hours?)",
    re.IGNORECASE,
)
IMMIGRATION_RE = re.compile(
    r"(?:비자|영주권|체류|visa|permit|residen|WHV|IEC|AEWV|PGWP|SMC|"
    r"ビザ|永住|滞在)",
    re.IGNORECASE,
)
CATEGORY_PATTERNS = {
    "fee": re.compile(
        r"(?:신청비|수수료|비자비|fee(?:s)?|application cost|申請費|手数料|料金)",
        re.IGNORECASE,
    ),
    "age": re.compile(
        r"(?:연령|나이|age\b|\d[\d\s–~〜～-]*세\b|\d[\d\s–~〜～-]*歳)",
        re.IGNORECASE,
    ),
    "quota": re.compile(
        r"(?:쿼터|정원|선발권|quota|定員|枠)",
        re.IGNORECASE,
    ),
    "wage": re.compile(
        r"(?:최저임금|중위임금|시급|연봉|급여|minimum wage|median wage|"
        r"hourly wage|salary|最低賃金|中央値賃金|時給|年収|給与)",
        re.IGNORECASE,
    ),
    "tax": re.compile(
        r"(?:세율|소득세|원천징수|tax(?: rate)?|income tax|税率|所得税)",
        re.IGNORECASE,
    ),
    "funds": re.compile(
        r"(?:자금증명|생활비 증명|proof of funds|financial support|"
        r"settlement funds|資金証明|生活費証明)",
        re.IGNORECASE,
    ),
    "processing": re.compile(
        r"(?:처리(?:기간)?|processing(?: time)?|処理(?:期間)?)",
        re.IGNORECASE,
    ),
    "duration": re.compile(
        r"(?:체류기간|유효기간|근무기간|기간|만료|stay|duration|valid for|"
        r"滞在期間|有効期間|勤務期間|期間)",
        re.IGNORECASE,
    ),
}


@dataclass(frozen=True)
class Candidate:
    page: str
    selector: str
    fingerprint: str
    category: str
    numbers: tuple[str, ...]
    text: str
    line: int
    directly_marked: bool = False

    @property
    def exemption_key(self) -> tuple[str, str]:
        return (self.selector, self.fingerprint)


@dataclass(frozen=True)
class CoverageIssue:
    code: str
    selector: str
    field: str
    actual: str
    expected: str
    fix: str

    def render(self) -> str:
        return (
            f"ERROR code={self.code} selector={self.selector} field={self.field} "
            f"actual={self.actual!r} expected={self.expected!r}\n"
            f"  Fix: {self.fix}"
        )


@dataclass
class CoverageReport:
    issues: list[CoverageIssue] = field(default_factory=list)
    candidate_count: int = 0
    marked_count: int = 0
    exempted_count: int = 0
    uncovered: list[Candidate] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues


@dataclass
class _Frame:
    tag: str
    selector: str
    line: int
    ignored: bool
    marked: bool
    own_claim: bool
    claim_id: str
    text: list[str] = field(default_factory=list)
    child_counts: dict[str, int] = field(default_factory=dict)


def _normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).strip()


def _mask_js_strings_and_comments(source: str) -> str:
    """Preserve code positions while removing non-code numeric noise."""

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
            if char == "\\" and index + 1 < len(source):
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


def _fingerprint(category: str, text: str) -> str:
    payload = f"{category}|{_normalized_text(text)}".encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()[:20]


def _normalize_number(raw: str) -> str | None:
    multiplier = Decimal(1)
    if raw[-1:].lower() == "k":
        multiplier = Decimal(1000)
        raw = raw[:-1]
    elif raw[-1:].lower() == "m":
        multiplier = Decimal(1000000)
        raw = raw[:-1]
    value = raw.replace(",", "").replace("−", "-")
    try:
        number = Decimal(value) * multiplier
    except InvalidOperation:
        return None
    if not number.is_finite():
        return None
    if number == number.to_integral():
        return str(int(number))
    return format(number.normalize(), "f")


def _number_is_date(text: str, start: int, end: int, normalized: str) -> bool:
    if re.fullmatch(r"20\d{2}", normalized):
        return True
    if any(
        match.start() <= start and end <= match.end()
        for match in DATE_SPAN_RE.finditer(text)
    ):
        return True
    return False


def _local_context(text: str, start: int, end: int) -> str:
    separators = list(
        re.finditer(
            r"(?:'\s*,\s*'|\s+[—–]\s+|[·;+。!?]|\.(?=\s))",
            text,
        )
    )
    left = max(
        (match.end() for match in separators if match.end() <= start),
        default=0,
    )
    right = min(
        (match.start() for match in separators if match.start() >= end),
        default=len(text),
    )
    return text[left:right]


def _numbers_for_category(
    text: str, category: str, *, require_keyword: bool = True
) -> tuple[str, ...]:
    numbers: list[str] = []
    for match in NUMBER_RE.finditer(text):
        normalized = _normalize_number(match.group())
        if normalized is None or _number_is_date(
            text, match.start(), match.end(), normalized
        ):
            continue
        unsigned = normalized.lstrip("-")
        if unsigned in VISA_IDENTIFIERS:
            continue
        if len(unsigned.split(".")[0]) >= 8:
            continue
        try:
            numeric = abs(Decimal(normalized))
        except InvalidOperation:
            continue

        context = _local_context(text, match.start(), match.end())
        if require_keyword and not CATEGORY_PATTERNS[category].search(context):
            currency_nearby = re.search(
                r"(?:NZD|CAD|AUD|\$)",
                context,
                re.IGNORECASE,
            )
            if not (
                category == "fee"
                and currency_nearby
                and IMMIGRATION_RE.search(context)
            ):
                continue

        nearby = text[max(0, match.start() - 8) : match.end() + 12]
        if category == "age" and not (
            numeric <= 100
            and (
                re.search(r"(?:세|歳|years?\s*old)", nearby, re.IGNORECASE)
                or re.search(r"(?:age|연령|나이)", nearby, re.IGNORECASE)
            )
        ):
            continue
        if category == "age" and re.match(
            r"\s*(?:점|points?\b)", text[match.end() :], re.IGNORECASE
        ):
            continue
        if category in {"duration", "processing"} and not (
            TIME_UNIT_RE.search(nearby)
            or (category == "processing" and "%" in nearby)
        ):
            continue
        if category == "wage":
            after = text[match.end() : match.end() + 12]
            if re.match(
                r"\s*(?:h(?:ours?)?\b|시간|개월|か月|ヶ月|년|年|주|週|일|日)",
                after,
                re.IGNORECASE,
            ) and not re.match(r"\s*/\s*h\b", after, re.IGNORECASE):
                continue
            if re.match(r"\s*(?:점|points?\b)", after, re.IGNORECASE):
                continue
        if category == "quota" and numeric < 100:
            continue
        if category == "funds" and numeric < 100:
            continue
        numbers.append(normalized)
    return tuple(dict.fromkeys(numbers))


def _categories_for_text(text: str) -> dict[str, tuple[str, ...]]:
    normalized = _normalized_text(text)
    categories: dict[str, tuple[str, ...]] = {}
    processing = bool(CATEGORY_PATTERNS["processing"].search(normalized))
    for category, pattern in CATEGORY_PATTERNS.items():
        if not pattern.search(normalized):
            continue
        if category == "duration":
            if processing or not TIME_UNIT_RE.search(normalized):
                continue
            if not IMMIGRATION_RE.search(normalized):
                continue
        numbers = _numbers_for_category(normalized, category)
        if numbers:
            categories[category] = numbers
    return categories


def _safe_id_selector(element_id: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", element_id):
        return "#" + element_id
    escaped = element_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'[id="{escaped}"]'


class _CoverageHTMLParser(HTMLParser):
    def __init__(self, page: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page = page
        self.frames: list[_Frame] = []
        self.candidates: list[Candidate] = []
        self.marked_facts: dict[str, set[str]] = {}

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        parent = self.frames[-1] if self.frames else None
        if parent:
            parent.child_counts[tag] = parent.child_counts.get(tag, 0) + 1
            index = parent.child_counts[tag]
        else:
            index = 1

        element_id = attrs_dict.get("id")
        if element_id:
            local_selector = _safe_id_selector(element_id)
            selector = f"{self.page}::{local_selector}"
        else:
            local_selector = f"{tag}:nth-of-type({index})"
            base = parent.selector if parent else f"{self.page}::"
            separator = ">" if not base.endswith("::") else ""
            selector = base + separator + local_selector

        context = " ".join(
            [attrs_dict.get("id", ""), attrs_dict.get("class", "")]
        )
        ignored = (
            tag in IGNORED_TAGS
            or bool(parent and parent.ignored)
            or bool(IGNORED_CONTEXT.search(context))
        )
        own_claim = "data-claim-id" in attrs_dict
        marked = own_claim or bool(parent and parent.marked)
        frame = _Frame(
            tag=tag,
            selector=selector,
            line=self.getpos()[0],
            ignored=ignored,
            marked=marked,
            own_claim=own_claim,
            claim_id=attrs_dict.get("data-claim-id", ""),
        )
        self.frames.append(frame)

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        for frame in self.frames:
            frame.text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if not self.frames:
            return
        index = len(self.frames) - 1
        while index >= 0 and self.frames[index].tag != tag:
            index -= 1
        if index < 0:
            return
        while len(self.frames) > index:
            frame = self.frames.pop()
            self._finish_frame(frame)

    def close(self) -> None:
        super().close()
        while self.frames:
            self._finish_frame(self.frames.pop())

    def _finish_frame(self, frame: _Frame) -> None:
        if frame.ignored or (
            frame.tag not in SEMANTIC_TAGS and not frame.own_claim
        ):
            return
        text = _normalized_text("".join(frame.text))
        if not text:
            return
        categories = _categories_for_text(text)
        if frame.own_claim:
            inferred = _categories_for_claim_id(frame.claim_id)
            for category in inferred:
                numbers = _numbers_for_category(
                    text, category, require_keyword=False
                )
                if numbers:
                    categories[category] = tuple(
                        dict.fromkeys(categories.get(category, ()) + numbers)
                    )
        for category, numbers in categories.items():
            candidate = Candidate(
                page=self.page,
                selector=frame.selector,
                fingerprint=_fingerprint(category, text),
                category=category,
                numbers=numbers,
                text=text,
                line=frame.line,
                directly_marked=frame.marked,
            )
            self.candidates.append(candidate)
            if frame.marked:
                self.marked_facts.setdefault(category, set()).update(numbers)


def _categories_for_claim_id(claim_id: str) -> set[str]:
    normalized = claim_id.lower()
    categories: set[str] = set()
    patterns = {
        "fee": r"(?:^|-)(?:fee|fees|ivl)(?:-|$)",
        "age": r"(?:^|-)age(?:-|$)",
        "quota": r"(?:^|-)(?:quota|cap)(?:-|$)",
        "wage": r"(?:^|-)(?:wage|median|csit|ssit)(?:-|$)",
        "tax": r"(?:^|-)(?:tax|netpay|acc)(?:-|$)",
        "funds": r"(?:^|-)funds?(?:-|$)",
        "processing": r"(?:^|-)(?:processing|service-standard)(?:-|$)",
        "duration": r"(?:^|-)(?:duration|second-work|third-work|overstay|reentry-ban|pr-eligibility)(?:-|$)",
    }
    for category, pattern in patterns.items():
        if re.search(pattern, normalized):
            categories.add(category)
    return categories


def _extract_main_script(html: str) -> str:
    blocks = [
        match.group(2)
        for match in re.finditer(
            r"<script([^>]*)>([\s\S]*?)</script>", html, re.IGNORECASE
        )
        if not re.search(r"\bsrc\s*=", match.group(1))
    ]
    return next((block for block in blocks if "const DB =" in block), "")


def _structured_script_candidates(page: str, script: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    script = textwrap.dedent(script)
    lines = script.splitlines()
    in_db = False
    section: str | None = None
    pathway_id = "unknown"
    selector_counts: dict[str, int] = {}

    for line_number, line in enumerate(lines, 1):
        if line.startswith("const DB = {"):
            in_db = True
            continue
        if in_db and line == "};":
            in_db = False
            section = None
            continue
        if not in_db:
            continue

        section_match = re.match(r"^  ([A-Za-z][A-Za-z0-9_]*):\s*[\[{]", line)
        if section_match:
            section = section_match.group(1)

        if section in {"wages", "fees", "estimates"}:
            value_match = re.match(
                r"^    ([A-Za-z][A-Za-z0-9_]*):\s*\{\s*v:\s*(.*?),\s*src:",
                line,
            )
            if value_match:
                key, value_text = value_match.groups()
                category = "wage" if section == "wages" else "fee"
                if section == "estimates":
                    if not re.search(r"(?:living|fund|settlement)", key, re.I):
                        continue
                    category = "funds"
                numbers = _numbers_for_category(
                    value_text, category, require_keyword=False
                )
                if numbers:
                    selector = f"{page}::script#DB.{section}.{key}"
                    text = f"{section}.{key} value {value_text}"
                    candidates.append(
                        Candidate(
                            page,
                            selector,
                            _fingerprint(category, text),
                            category,
                            numbers,
                            _normalized_text(text),
                            line_number,
                        )
                    )

        if section == "pathways":
            id_match = re.match(r"^\s{6}id:\s*'([^']+)'", line)
            if id_match:
                pathway_id = id_match.group(1)
            for field_name, category in (
                ("duration", "duration"),
                ("processing", "processing"),
                ("requirements", "duration"),
            ):
                if not re.search(rf"\b{field_name}\s*:", line):
                    continue
                text = _normalized_text(line)
                if field_name == "requirements":
                    detected = _categories_for_text(text)
                    pairs = list(detected.items())
                else:
                    field_match = re.search(
                        rf"\b{field_name}\s*:\s*('(?:\\.|[^'])*'|\[(?:\\.|[^\]])*\])",
                        line,
                    )
                    value_text = field_match.group(1) if field_match else text
                    numbers = _numbers_for_category(
                        value_text, category, require_keyword=False
                    )
                    pairs = [(category, numbers)] if numbers else []
                for detected_category, numbers in pairs:
                    base = (
                        f"{page}::script#DB.pathways.{pathway_id}.{field_name}"
                    )
                    selector_counts[base] = selector_counts.get(base, 0) + 1
                    selector = f"{base}[{selector_counts[base]}]"
                    candidates.append(
                        Candidate(
                            page,
                            selector,
                            _fingerprint(detected_category, text),
                            detected_category,
                            numbers,
                            text,
                            line_number,
                        )
                    )

    for constant in ("NP_BRACKETS", "CA_TAX", "AU_TAX"):
        match = re.search(
            rf"\bconst\s+{constant}\s*=\s*([\s\S]*?);\s*(?:\n|$)", script
        )
        if not match:
            continue
        text = _normalized_text(match.group(0))
        numbers = _numbers_for_category(
            _mask_js_strings_and_comments(match.group(0)),
            "tax",
            require_keyword=False,
        )
        if numbers:
            candidates.append(
                Candidate(
                    page,
                    f"{page}::script#{constant}",
                    _fingerprint("tax", text),
                    "tax",
                    numbers,
                    text,
                    script[: match.start()].count("\n") + 1,
                )
            )
    return candidates


def collect_candidates(
    root: Path | str, pages: tuple[str, ...] | list[str] = DEFAULT_PAGES
) -> tuple[list[Candidate], dict[str, dict[str, set[str]]], list[CoverageIssue]]:
    root_path = Path(root).resolve()
    candidates: list[Candidate] = []
    marked_by_page: dict[str, dict[str, set[str]]] = {}
    issues: list[CoverageIssue] = []

    for page in pages:
        page_path = (root_path / page).resolve()
        try:
            page_path.relative_to(root_path)
        except ValueError:
            issues.append(
                CoverageIssue(
                    "INVALID_PAGE",
                    page,
                    "path",
                    page,
                    "repository-relative path",
                    "Remove '..' or absolute path components.",
                )
            )
            continue
        if not page_path.is_file():
            issues.append(
                CoverageIssue(
                    "MISSING_PAGE",
                    page,
                    "path",
                    str(page_path),
                    "existing HTML file",
                    "Create the page or correct the configured path.",
                )
            )
            continue
        try:
            html = page_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            issues.append(
                CoverageIssue(
                    "UNREADABLE_PAGE",
                    page,
                    "encoding",
                    str(exc),
                    "readable UTF-8 HTML",
                    "Save the page as UTF-8 and make it readable.",
                )
            )
            continue

        parser = _CoverageHTMLParser(page)
        parser.feed(html)
        parser.close()
        candidates.extend(parser.candidates)
        marked_by_page[page] = parser.marked_facts
        script = _extract_main_script(html)
        if script:
            candidates.extend(_structured_script_candidates(page, script))

    unique: dict[tuple[str, str, str], Candidate] = {}
    for candidate in candidates:
        unique[(candidate.selector, candidate.fingerprint, candidate.category)] = (
            candidate
        )
    return list(unique.values()), marked_by_page, issues


def _load_exemptions(
    path: Path, today: date, issues: list[CoverageIssue]
) -> list[dict[str, str]]:
    if not path.is_file():
        issues.append(
            CoverageIssue(
                "MISSING_EXEMPTIONS",
                str(path),
                "file",
                "missing",
                "schemaVersion 1 exemption registry",
                f"Create {DEFAULT_EXEMPTIONS} with an exemptions array.",
            )
        )
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        issues.append(
            CoverageIssue(
                "INVALID_EXEMPTIONS",
                str(path),
                "json",
                str(exc),
                "valid UTF-8 JSON",
                "Repair the exemption registry JSON.",
            )
        )
        return []
    if (
        not isinstance(data, dict)
        or data.get("schemaVersion") != 1
        or not isinstance(data.get("exemptions"), list)
    ):
        issues.append(
            CoverageIssue(
                "INVALID_EXEMPTIONS",
                str(path),
                "schema",
                repr(data)[:200],
                "{schemaVersion: 1, exemptions: []}",
                "Use the documented root schema.",
            )
        )
        return []

    valid: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, exemption in enumerate(data["exemptions"]):
        selector = (
            exemption.get("selector", f"<exemption {index + 1}>")
            if isinstance(exemption, dict)
            else f"<exemption {index + 1}>"
        )
        if not isinstance(exemption, dict):
            issues.append(
                CoverageIssue(
                    "INVALID_EXEMPTION",
                    selector,
                    "entry",
                    type(exemption).__name__,
                    "object",
                    "Replace the entry with an exemption object.",
                )
            )
            continue
        invalid = False
        for field_name in EXEMPTION_FIELDS:
            value = exemption.get(field_name)
            if not isinstance(value, str) or not value.strip():
                invalid = True
                issues.append(
                    CoverageIssue(
                        "INVALID_EXEMPTION",
                        selector,
                        field_name,
                        repr(value),
                        "non-empty string",
                        f"Set a non-empty {field_name}.",
                    )
                )
        if invalid:
            continue
        try:
            expires_at = date.fromisoformat(exemption["expiresAt"])
        except ValueError:
            issues.append(
                CoverageIssue(
                    "INVALID_EXEMPTION",
                    selector,
                    "expiresAt",
                    exemption["expiresAt"],
                    "ISO date YYYY-MM-DD",
                    "Use a real calendar date.",
                )
            )
            continue
        key = (exemption["selector"], exemption["fingerprint"])
        if key in seen:
            issues.append(
                CoverageIssue(
                    "DUPLICATE_EXEMPTION",
                    selector,
                    "fingerprint",
                    exemption["fingerprint"],
                    "unique selector/fingerprint pair",
                    "Remove the duplicate exemption.",
                )
            )
            continue
        seen.add(key)
        if expires_at < today:
            issues.append(
                CoverageIssue(
                    "EXPIRED_EXEMPTION",
                    selector,
                    "expiresAt",
                    exemption["expiresAt"],
                    f">= {today.isoformat()}",
                    "Review the candidate, then renew or remove the exemption.",
                )
            )
        valid.append(exemption)
    return valid


def _verify_public_coverage_summary(
    root: Path, report: CoverageReport
) -> None:
    registry_path = root / DEFAULT_CLAIM_REGISTRY
    if not registry_path.is_file():
        return
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        report.issues.append(
            CoverageIssue(
                "INVALID_PUBLIC_COVERAGE",
                DEFAULT_CLAIM_REGISTRY,
                "json",
                str(exc),
                "readable claim registry JSON",
                "Repair data/claims.json before publishing coverage totals.",
            )
        )
        return
    summary = (
        registry.get("audit", {}).get("coverage")
        if isinstance(registry, dict)
        else None
    )
    if not isinstance(summary, dict):
        report.issues.append(
            CoverageIssue(
                "MISSING_PUBLIC_COVERAGE",
                DEFAULT_CLAIM_REGISTRY,
                "audit.coverage",
                repr(summary),
                "candidateCount, markedCount, exemptionCount",
                "Publish the current verifier totals in audit.coverage.",
            )
        )
        return
    expected = {
        "candidateCount": report.candidate_count,
        "markedCount": report.marked_count,
        "exemptionCount": report.exempted_count,
    }
    for field_name, actual in expected.items():
        if summary.get(field_name) != actual:
            report.issues.append(
                CoverageIssue(
                    "PUBLIC_COVERAGE_MISMATCH",
                    DEFAULT_CLAIM_REGISTRY,
                    f"audit.coverage.{field_name}",
                    repr(summary.get(field_name)),
                    str(actual),
                    "Update the public coverage total only after rerunning "
                    "scripts/verify_claim_coverage.py.",
                )
            )


def verify_coverage(
    root: Path | str,
    *,
    pages: tuple[str, ...] | list[str] = DEFAULT_PAGES,
    exemptions_path: Path | str = DEFAULT_EXEMPTIONS,
    today: date | None = None,
) -> CoverageReport:
    report = CoverageReport()
    root_path = Path(root).resolve()
    candidates, marked_by_page, collection_issues = collect_candidates(
        root_path, pages
    )
    report.issues.extend(collection_issues)
    report.candidate_count = len(candidates)
    today_value = today or datetime.now(timezone.utc).date()
    exemption_file = Path(exemptions_path)
    if not exemption_file.is_absolute():
        exemption_file = root_path / exemption_file
    exemptions = _load_exemptions(exemption_file, today_value, report.issues)
    exemption_map = {
        (item["selector"], item["fingerprint"]): item for item in exemptions
    }
    exemption_targets: set[tuple[str, str]] = set()

    for candidate in candidates:
        page_facts = marked_by_page.get(candidate.page, {})
        globally_marked = set(candidate.numbers).issubset(
            page_facts.get(candidate.category, set())
        )
        if candidate.directly_marked or globally_marked:
            report.marked_count += 1
            continue
        exemption_targets.add(candidate.exemption_key)
        exemption = exemption_map.get(candidate.exemption_key)
        if exemption and date.fromisoformat(exemption["expiresAt"]) >= today_value:
            report.exempted_count += 1
            continue
        report.uncovered.append(candidate)
        report.issues.append(
            CoverageIssue(
                "UNCOVERED_CLAIM",
                candidate.selector,
                f"{candidate.category}@line{candidate.line}",
                f"{candidate.numbers} {candidate.text[:180]}",
                f'data-claim-id coverage or exemption fingerprint {candidate.fingerprint}',
                "Add a data-claim-id marker for this fact. If it is intentionally "
                "out of registry scope, add a reviewed exemption with selector, "
                "fingerprint, reason, owner, and expiresAt.",
            )
        )

    for key, exemption in exemption_map.items():
        if key not in exemption_targets:
            report.issues.append(
                CoverageIssue(
                    "ORPHAN_EXEMPTION",
                    exemption["selector"],
                    "fingerprint",
                    exemption["fingerprint"],
                    "an existing uncovered candidate",
                    "Remove the exemption, or update selector/fingerprint only after "
                    "reviewing the changed candidate.",
                )
            )
    _verify_public_coverage_summary(root_path, report)
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find unregistered sensitive numeric claims in country HTML."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    parser.add_argument(
        "--exemptions",
        default=DEFAULT_EXEMPTIONS,
        help=f"exemption registry (default: {DEFAULT_EXEMPTIONS})",
    )
    parser.add_argument(
        "--page",
        action="append",
        dest="pages",
        help="page to scan; repeat to override the four default editions",
    )
    parser.add_argument(
        "--dump-uncovered",
        action="store_true",
        help="print uncovered candidates as JSON after normal errors",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    pages = tuple(args.pages) if args.pages else DEFAULT_PAGES
    report = verify_coverage(
        args.root,
        pages=pages,
        exemptions_path=args.exemptions,
    )
    if not report.ok:
        print(
            f"Claim coverage verification failed with {len(report.issues)} error(s):",
            file=sys.stderr,
        )
        for issue in report.issues:
            print(issue.render(), file=sys.stderr)
        if args.dump_uncovered:
            suggestions = [
                {
                    "selector": item.selector,
                    "fingerprint": item.fingerprint,
                    "reason": "REVIEW REQUIRED",
                    "owner": "REVIEW REQUIRED",
                    "expiresAt": "YYYY-MM-DD",
                    "_category": item.category,
                    "_numbers": list(item.numbers),
                    "_text": item.text,
                }
                for item in report.uncovered
            ]
            print(json.dumps(suggestions, ensure_ascii=False, indent=2))
        return 1
    print(
        "Claim coverage verification passed: "
        f"{report.candidate_count} candidate(s), "
        f"{report.marked_count} marked, {report.exempted_count} exempted."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
