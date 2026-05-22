"""Unit tests for PII redactor module."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


class TestPIIRedaction:
    """Comprehensive PII redaction tests."""

    def test_email_redacted(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("Contact: user.name+tag@company.co.uk")
        assert "[REDACTED_EMAIL]" in r.redacted_text
        assert "user.name" not in r.redacted_text

    def test_email_count(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("Email1: a@b.com, Email2: c@d.org")
        assert r.count >= 2

    def test_uk_phone_redacted(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("Mobile: +44 7700 900123")
        assert "7700 900123" not in r.redacted_text

    def test_linkedin_redacted(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("See my profile: https://www.linkedin.com/in/john-doe-engineer")
        assert "john-doe-engineer" not in r.redacted_text
        assert "[REDACTED_LINKEDIN]" in r.redacted_text

    def test_github_redacted(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("GitHub: https://github.com/janedoe")
        assert "janedoe" not in r.redacted_text
        assert "[REDACTED_GITHUB]" in r.redacted_text

    def test_uk_postcode_redacted(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("Address: 10 Downing Street, London SW1A 2AA")
        assert "SW1A 2AA" not in r.redacted_text

    def test_ni_number_redacted(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("NI Number: QQ 12 34 56 C")
        assert "QQ 12 34 56 C" not in r.redacted_text

    def test_no_pii_unchanged(self):
        from safety.pii_redactor import redact_pii
        text = "7 years experience with Apache Spark, Kafka, and Python."
        r = redact_pii(text)
        assert r.count == 0
        assert r.redacted_text == text

    def test_pii_types_in_report(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("email@test.com and https://github.com/user123")
        assert len(r.pii_types_found) >= 1

    def test_redacted_text_in_report(self):
        from safety.pii_redactor import redact_pii
        r = redact_pii("Call me on +44 7911 123456 or email test@example.com")
        assert r.redacted_text is not None
        assert len(r.redacted_text) > 0

    def test_check_pii_always_passes(self):
        """PII check should always pass (redaction is the mitigation, not a blocker)."""
        from safety.pii_redactor import check_pii
        result, redacted = check_pii("Email: user@test.com Phone: +44 7700 123456", "cv")
        assert result.passed  # never blocks
        assert "[REDACTED_EMAIL]" in redacted

    def test_check_pii_returns_redacted_text(self):
        from safety.pii_redactor import check_pii
        _, redacted = check_pii("Contact john.doe@example.org for details.", "cv")
        assert "john.doe@example.org" not in redacted
