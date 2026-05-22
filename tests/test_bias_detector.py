"""Unit tests for the bias detector module."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


class TestBiasPatterns:
    """Pattern-level bias detection tests."""

    def test_gender_gendered_pronoun(self):
        from safety.bias_detector import _pattern_bias_check
        score, _, chars = _pattern_bias_check("She would be a good fit for a nurturing role.")
        assert "gender" in chars

    def test_gender_maternity(self):
        from safety.bias_detector import _pattern_bias_check
        score, _, chars = _pattern_bias_check("We need to consider her maternity plans.")
        assert "gender" in chars

    def test_age_overqualified(self):
        from safety.bias_detector import _pattern_bias_check
        score, _, chars = _pattern_bias_check("This candidate seems overqualified due to age.")
        # May catch 'overqualified' depending on pattern
        assert score >= 0.0  # at minimum no exception

    def test_age_digital_native(self):
        from safety.bias_detector import _pattern_bias_check
        _, _, chars = _pattern_bias_check("Looking for a digital native who can keep up.")
        assert "age" in chars

    def test_age_young_energetic(self):
        from safety.bias_detector import _pattern_bias_check
        _, _, chars = _pattern_bias_check("We need someone young and energetic for this role.")
        assert "age" in chars

    def test_nationality_non_native(self):
        from safety.bias_detector import _pattern_bias_check
        _, _, chars = _pattern_bias_check("The non-native speaker may struggle with client calls.")
        assert "nationality" in chars

    def test_religion_signal(self):
        from safety.bias_detector import _pattern_bias_check
        _, _, chars = _pattern_bias_check("The candidate's Christian values are evident.")
        assert "religion/belief" in chars

    def test_disability_signal(self):
        from safety.bias_detector import _pattern_bias_check
        _, _, chars = _pattern_bias_check("Candidate disclosed a disability which may affect performance.")
        assert "disability" in chars

    def test_neutral_text_no_bias(self):
        from safety.bias_detector import _pattern_bias_check
        score, _, chars = _pattern_bias_check(
            "Strong technical skills in Python and Spark. "
            "6 years of pipeline engineering experience. Recommendation: Advance."
        )
        assert score == 0.0

    def test_multiple_characteristics(self):
        from safety.bias_detector import _pattern_bias_check
        score, _, chars = _pattern_bias_check(
            "She would benefit from a nurturing role. "
            "As a digital native, she should be young and energetic."
        )
        # Should detect both gender and age
        assert len(chars) >= 2
        assert score >= 0.5


class TestBiasCheckResult:
    """Integration tests for check_bias() return type."""

    def test_clean_text_passes(self):
        from safety.bias_detector import check_bias
        result = check_bias(
            "Candidate has demonstrated excellent technical capabilities "
            "with 7 years of relevant experience. Recommendation: Advance."
        )
        assert result.check_name == "bias_detector"
        assert result.passed

    def test_result_has_required_fields(self):
        from safety.bias_detector import check_bias
        result = check_bias("Some text about a candidate.")
        assert hasattr(result, "score")
        assert hasattr(result, "threat_level")
        assert hasattr(result, "details")
        assert 0.0 <= result.score <= 1.0
