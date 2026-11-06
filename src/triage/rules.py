"""Deterministic phishing checks.

These rules set the minimum risk level for a report (see ADR-0002).
They only read the email as text. Links are never fetched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

LEVELS = ("low", "medium", "high")

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta",
    ".iso", ".img", ".lnk", ".docm", ".xlsm", ".pptm", ".html", ".htm",
}

INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(ai|assistant|language model|llm|classifier)\b.{0,40}\b(classify|mark|treat|label|rate)\b",
        r"ignore (all |any )?(previous|prior|above) instructions",
        r"\bthis (email|message) is (safe|legitimate|not phishing)\b",
    )
]


@dataclass
class Finding:
    rule: str
    level: str
    detail: str


@dataclass
class RulesResult:
    level: str = "low"
    findings: list[Finding] = field(default_factory=list)

    def add(self, rule: str, level: str, detail: str) -> None:
        self.findings.append(Finding(rule, level, detail))
        self.level = max_level(self.level, level)


def max_level(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def parse_eml(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)


def _domain(address_header: str | None) -> str:
    _, addr = parseaddr(address_header or "")
    return addr.rpartition("@")[2].lower()


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    plain, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain += part.get_content()
        elif ctype == "text/html":
            html += part.get_content()
    return plain, html


def check_headers(msg: EmailMessage, result: RulesResult) -> None:
    from_dom = _domain(msg.get("From"))
    reply_dom = _domain(msg.get("Reply-To"))
    if reply_dom and from_dom and reply_dom != from_dom:
        result.add("reply_to_mismatch", "medium",
                   f"Replies go to {reply_dom}, not the sender's domain {from_dom}.")

    auth = (msg.get("Authentication-Results") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mech}=(fail|softfail)\b", auth):
            level = "high" if mech == "dmarc" else "medium"
            result.add(f"{mech}_fail", level, f"{mech.upper()} check failed.")


def check_links(html: str, result: RulesResult) -> None:
    collector = _LinkCollector()
    collector.feed(html)
    for href, text in collector.links:
        target = urlparse(href).hostname or ""
        shown = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", text.lower())
        if shown and target and not target.lower().endswith(shown.group(0)):
            result.add("link_text_mismatch", "high",
                       f"Link text shows {shown.group(0)} but points to {target}.")
        if re.fullmatch(r"[\d.]+", target):
            result.add("ip_address_link", "medium", f"Link points to a bare IP address: {target}.")


def check_attachments(msg: EmailMessage, result: RulesResult) -> None:
    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in RISKY_EXTENSIONS:
            result.add("risky_attachment", "high",
                       f"Attachment type {ext} is commonly used for malware: {name}.")


def check_injection(text: str, result: RulesResult) -> None:
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            result.add("ai_instruction_text", "high",
                       "The email contains text addressed to an AI system, a sign of an evasion attempt.")
            return


def evaluate(raw: bytes) -> RulesResult:
    msg = parse_eml(raw)
    result = RulesResult()
    plain, html = _bodies(msg)
    check_headers(msg, result)
    check_links(html, result)
    check_attachments(msg, result)
    check_injection(plain + "\n" + html, result)
    return result
