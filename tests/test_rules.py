from pathlib import Path

import pytest

from triage.rules import evaluate, max_level

SAMPLES = Path(__file__).parent / "samples"


def load(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def rules_hit(result) -> set[str]:
    return {f.rule for f in result.findings}


def test_invoice_phish_is_high_risk():
    result = evaluate(load("phish_invoice.eml"))
    assert result.level == "high"
    assert {"reply_to_mismatch", "spf_fail", "dmarc_fail",
            "link_text_mismatch", "ip_address_link", "risky_attachment"} <= rules_hit(result)


def test_injection_text_is_flagged_high():
    result = evaluate(load("phish_injection.eml"))
    assert result.level == "high"
    assert "ai_instruction_text" in rules_hit(result)


def test_legit_newsletter_is_low_risk():
    result = evaluate(load("legit_newsletter.eml"))
    assert result.level == "low"
    assert result.findings == []


@pytest.mark.parametrize("a,b,expected", [
    ("low", "high", "high"),
    ("high", "low", "high"),
    ("medium", "low", "medium"),
])
def test_max_level_never_lowers(a, b, expected):
    assert max_level(a, b) == expected
