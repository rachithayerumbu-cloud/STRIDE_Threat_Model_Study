"""
Tests for STRIDE Threat Model Analyzer
======================================
Run with:  python -m pytest tests/ -v
"""

import sys
import os
import json

# Ensure project root is on the path so modules can be imported directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from modules.stride_engine import analyse_system, STRIDE_CATEGORIES
from modules.risk_calculator import calculate_risk, enrich_threats, build_summary
from modules.report_generator import generate_text_report, generate_csv_report


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_system():
    """Load the built-in sample system from the JSON file."""
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_system.json")
    with open(data_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def minimal_system():
    """A minimal two-component system for edge-case testing."""
    return {
        "name": "Simple Web App",
        "description": "A minimal system with a user and a web app.",
        "components": [
            {"id": "u1", "name": "End User", "type": "user", "description": "Browser client."},
            {"id": "w1", "name": "Web Server", "type": "web_application", "description": "Flask app."},
        ],
        "data_flows": [
            {"id": "df1", "from": "u1", "to": "w1", "label": "HTTP request", "protocol": "HTTPS"},
        ],
        "trust_boundaries": [],
    }


@pytest.fixture
def db_system():
    """System that includes a database to trigger database-related threats."""
    return {
        "name": "DB System",
        "description": "Web app with database.",
        "components": [
            {"id": "u1", "name": "User", "type": "user",            "description": ""},
            {"id": "w1", "name": "App",  "type": "web_application", "description": ""},
            {"id": "d1", "name": "DB",   "type": "database",        "description": ""},
        ],
        "data_flows": [],
        "trust_boundaries": [],
    }


# ── Test: Assessment Creation ────────────────────────────────────────────────

class TestAssessmentCreation:
    def test_analyse_sample_system_returns_threats(self, sample_system):
        """Running analysis on the sample system should return a non-empty threat list."""
        threats = analyse_system(sample_system)
        assert isinstance(threats, list), "analyse_system should return a list"
        assert len(threats) > 0, "Sample system should produce at least one threat"

    def test_analyse_minimal_system(self, minimal_system):
        """A user + web app system should still produce threats."""
        threats = analyse_system(minimal_system)
        assert len(threats) > 0

    def test_analyse_empty_components(self):
        """A system with no components should return no threats."""
        system = {"name": "Empty", "description": "No components", "components": [], "data_flows": [], "trust_boundaries": []}
        threats = analyse_system(system)
        assert threats == []

    def test_threat_has_required_keys(self, sample_system):
        """Every threat must contain the expected metadata keys."""
        required_keys = {"id", "category", "name", "affected_components", "description",
                         "likelihood", "impact", "mitigation", "security_control"}
        threats = analyse_system(sample_system)
        for threat in threats:
            missing = required_keys - set(threat.keys())
            assert not missing, f"Threat {threat.get('id')} is missing keys: {missing}"


# ── Test: STRIDE Threat Identification ──────────────────────────────────────

class TestSTRIDEIdentification:
    def test_all_stride_categories_present(self, sample_system):
        """The sample system should produce threats in all six STRIDE categories."""
        threats = analyse_system(sample_system)
        found_categories = {t["category"] for t in threats}
        expected = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                    "Denial of Service", "Elevation of Privilege"}
        missing = expected - found_categories
        assert not missing, f"Missing STRIDE categories: {missing}"

    def test_database_threats_require_database_component(self, minimal_system):
        """Threats tied to databases should NOT appear when there is no database component."""
        threats = analyse_system(minimal_system)
        # T1 (SQL Injection) requires web_application + database
        sql_injection = [t for t in threats if t["id"] == "T1"]
        # minimal_system has no database, so T1 should not be triggered
        assert len(sql_injection) == 0, "SQL Injection should not appear without a database"

    def test_database_threats_appear_with_database(self, db_system):
        """SQL Injection (T1) should appear when a database component is present."""
        threats = analyse_system(db_system)
        ids = [t["id"] for t in threats]
        assert "T1" in ids, "T1 (SQL Injection) should be identified when database is present"

    def test_no_duplicate_threat_ids(self, sample_system):
        """Each threat ID should appear only once in the results."""
        threats = analyse_system(sample_system)
        ids = [t["id"] for t in threats]
        assert len(ids) == len(set(ids)), "Duplicate threat IDs found"

    def test_stride_categories_list_has_six_entries(self):
        """STRIDE_CATEGORIES constant must have exactly 6 entries."""
        assert len(STRIDE_CATEGORIES) == 6

    def test_stride_category_letters(self):
        """Category letters must spell out STRIDE in order."""
        letters = [c["letter"] for c in STRIDE_CATEGORIES]
        assert letters == ["S", "T", "R", "I", "D", "E"]


# ── Test: Risk Level Calculation ─────────────────────────────────────────────

class TestRiskCalculation:
    @pytest.mark.parametrize("likelihood,impact,expected", [
        ("High",   "High",   "High"),
        ("High",   "Medium", "High"),
        ("High",   "Low",    "Medium"),
        ("Medium", "High",   "High"),
        ("Medium", "Medium", "Medium"),
        ("Medium", "Low",    "Low"),
        ("Low",    "High",   "Medium"),
        ("Low",    "Medium", "Low"),
        ("Low",    "Low",    "Low"),
    ])
    def test_risk_matrix(self, likelihood, impact, expected):
        assert calculate_risk(likelihood, impact) == expected

    def test_enrich_adds_risk_level(self, sample_system):
        """enrich_threats should add a 'risk_level' key to each threat."""
        threats = analyse_system(sample_system)
        enriched = enrich_threats(threats)
        for t in enriched:
            assert "risk_level" in t, f"Threat {t['id']} missing risk_level"
            assert t["risk_level"] in {"Low", "Medium", "High"}

    def test_summary_counts_match_threats(self, sample_system):
        """Summary total_threats should equal len(threats)."""
        threats = analyse_system(sample_system)
        threats = enrich_threats(threats)
        summary = build_summary(threats)
        assert summary["total_threats"] == len(threats)
        assert summary["risk_counts"]["High"] + summary["risk_counts"]["Medium"] + summary["risk_counts"]["Low"] == len(threats)

    def test_build_summary_empty(self):
        """build_summary on an empty list should return zeros."""
        summary = build_summary([])
        assert summary["total_threats"] == 0
        assert summary["risk_counts"]["High"] == 0


# ── Test: Report Generation ──────────────────────────────────────────────────

class TestReportGeneration:
    def test_text_report_contains_system_name(self, sample_system):
        threats = analyse_system(sample_system)
        threats = enrich_threats(threats)
        summary = build_summary(threats)
        report  = generate_text_report(sample_system, threats, summary)
        assert sample_system["name"] in report

    def test_text_report_contains_all_threat_ids(self, sample_system):
        threats = analyse_system(sample_system)
        threats = enrich_threats(threats)
        summary = build_summary(threats)
        report  = generate_text_report(sample_system, threats, summary)
        for t in threats:
            assert t["id"] in report

    def test_csv_report_has_header_row(self, sample_system):
        threats = analyse_system(sample_system)
        threats = enrich_threats(threats)
        csv_text = generate_csv_report(sample_system, threats)
        first_line = csv_text.split("\n")[0]
        assert "STRIDE Category" in first_line

    def test_csv_report_row_count(self, sample_system):
        """CSV should have header + one row per threat."""
        threats = analyse_system(sample_system)
        threats = enrich_threats(threats)
        csv_text = generate_csv_report(sample_system, threats)
        # Filter out any trailing blank lines
        lines = [l for l in csv_text.split("\n") if l.strip()]
        assert len(lines) == len(threats) + 1  # +1 for header

    def test_text_report_contains_stride_header(self, sample_system):
        threats = analyse_system(sample_system)
        threats = enrich_threats(threats)
        summary = build_summary(threats)
        report  = generate_text_report(sample_system, threats, summary)
        assert "STRIDE THREAT MODEL REPORT" in report


# ── Test: Invalid Input Handling ─────────────────────────────────────────────

class TestInvalidInput:
    def test_missing_name_field(self):
        """A system without a 'name' key should not crash; threats are still computed."""
        system = {
            "description": "No name here",
            "components": [{"id": "u1", "name": "User", "type": "user", "description": ""}],
            "data_flows": [],
            "trust_boundaries": [],
        }
        threats = analyse_system(system)
        # Should not raise; result type should be list
        assert isinstance(threats, list)

    def test_unknown_component_type(self):
        """An unrecognised component type should not crash the engine."""
        system = {
            "name": "Unknown Types",
            "description": "Uses an unknown component type.",
            "components": [
                {"id": "x1", "name": "Alien Device", "type": "quantum_processor", "description": ""}
            ],
            "data_flows": [],
            "trust_boundaries": [],
        }
        threats = analyse_system(system)
        assert isinstance(threats, list)
        # Unknown type matches no rule → 0 threats
        assert len(threats) == 0

    def test_risk_calculator_invalid_strings(self):
        """calculate_risk should default to Medium for unrecognised input."""
        result = calculate_risk("Unknown", "Gibberish")
        # Both default to score 2 → Medium
        assert result == "Medium"

    def test_enrich_threats_empty_list(self):
        """enrich_threats on an empty list should return an empty list."""
        result = enrich_threats([])
        assert result == []

    def test_csv_report_empty_threats(self, sample_system):
        """CSV with no threats should still have the header row."""
        csv_text = generate_csv_report(sample_system, [])
        lines = [l for l in csv_text.split("\n") if l.strip()]
        assert len(lines) == 1  # header only

    def test_text_report_no_components(self):
        """Text report should not crash when components list is empty."""
        system = {"name": "Empty", "description": "No parts.", "components": [], "data_flows": [], "trust_boundaries": []}
        threats = []
        summary = build_summary([])
        report  = generate_text_report(system, threats, summary)
        assert "STRIDE THREAT MODEL REPORT" in report
