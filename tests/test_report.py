"""Tests for Report Generator module."""

import tempfile
from pathlib import Path

import pytest

from atum_audit.annexe_iv import AnnexIVPoint, AnnexIVReport
from atum_audit.compliance import ComplianceManager
from atum_audit.report import ReportGenerator
from atum_audit.store import AuditStore
from atum_audit.validator import ValidationReport, Violation


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def ontology_path():
    p = Path(__file__).parent.parent / "atum_audit" / "ontology.ttl"
    if p.exists():
        return p
    pytest.fail(f"ontology.ttl not found at {p}")


@pytest.fixture
def store(tmp_dir, ontology_path):
    return AuditStore(tmp_dir / "store", ontology_path)


@pytest.fixture
def cm(store):
    return ComplianceManager(store)


@pytest.fixture
def generator():
    return ReportGenerator()


def _register_full_system(cm, store):
    """Register an AI system with model and incident for report testing."""
    sys_uri = cm.register_ai_system(
        "ReportTestSystem",
        risk_level="high_risk",
        intended_purpose="Compliance reporting",
        description="Test system for report generation",
        retention_months=12,
    )
    cm.register_model_version(
        sys_uri, "v1.0.0",
        performance_metrics={"accuracy": 0.92},
        training_data="train-data-1",
    )
    cm.report_incident(
        sys_uri, "INC-001", "Test incident", severity="high",
    )
    return sys_uri


class TestReportGenerator:
    def test_generate_html(self, generator):
        """Should generate HTML output."""
        data = {
            "system_name": "TestSystem",
            "timestamp": "2026-02-19",
            "version": "2.0.0",
            "risk_level": "HighRisk",
            "compliance_status": "Pending",
            "lifecycle_phase": "Development",
            "validation": None,
            "annex_iv": None,
            "violations": [],
            "incidents": [],
            "models": [],
        }
        html = generator.generate(data, fmt="html")
        assert "<!DOCTYPE html>" in html
        assert "TestSystem" in html
        assert "HighRisk" in html

    def test_generate_markdown(self, generator):
        """Should generate Markdown output."""
        data = {
            "system_name": "TestSystem",
            "timestamp": "2026-02-19",
            "version": "2.0.0",
            "risk_level": "MinimalRisk",
            "compliance_status": "Compliant",
            "lifecycle_phase": "Operation",
            "validation": None,
            "annex_iv": None,
            "violations": [],
            "incidents": [],
            "models": [],
        }
        md = generator.generate(data, fmt="md")
        assert "# Rapport de conformite" in md
        assert "TestSystem" in md

    def test_html_with_violations(self, generator):
        """HTML should include violations table when present."""
        data = {
            "system_name": "TestSystem",
            "timestamp": "2026-02-19",
            "version": "2.0.0",
            "risk_level": "HighRisk",
            "compliance_status": "NonCompliant",
            "lifecycle_phase": "Development",
            "validation": {"conforms": False, "stats": {"errors": 2, "warnings": 1}},
            "annex_iv": {
                "completeness_pct": 30.0,
                "points": [
                    {
                        "label": "Point 1", "article": "Annexe IV, pt. 1",
                        "pct": 50.0, "missing": ["field_a"],
                    },
                ],
            },
            "violations": [
                {
                    "severity": "Violation", "focus_node": "urn:test",
                    "path": "systemName", "message": "Missing",
                },
            ],
            "incidents": [],
            "models": [],
        }
        html = generator.generate(data, fmt="html")
        assert "Violations SHACL" in html
        assert "Missing" in html

    def test_plaintext_fallback(self, tmp_dir):
        """When Jinja2 is 'unavailable', should produce plaintext."""
        gen = ReportGenerator(template_dir=tmp_dir)  # no templates here
        data = {
            "system_name": "FallbackSystem",
            "timestamp": "2026-02-19",
            "risk_level": "MinimalRisk",
            "compliance_status": "Compliant",
            "lifecycle_phase": "Operation",
            "validation": {"conforms": True, "stats": {"errors": 0, "warnings": 0}},
            "annex_iv": None,
            "violations": [],
        }
        result = gen.generate(data, fmt="html")
        assert "FallbackSystem" in result
        assert "ATUM Audit Agent" in result

    def test_plaintext_with_annex_iv(self, tmp_dir):
        """Plaintext fallback should include Annex IV data."""
        gen = ReportGenerator(template_dir=tmp_dir)
        data = {
            "system_name": "TestSystem",
            "timestamp": "2026-02-19",
            "risk_level": "HighRisk",
            "compliance_status": "Pending",
            "lifecycle_phase": "Development",
            "validation": None,
            "annex_iv": {
                "completeness_pct": 50.0,
                "points": [
                    {"label": "Point 1", "pct": "100.0%", "missing": []},
                    {"label": "Point 2", "pct": "0.0%", "missing": ["field_a"]},
                ],
            },
            "violations": [],
        }
        result = gen.generate(data, fmt="html")
        assert "50.0%" in result


class TestComplianceReport:
    def test_full_report_html(self, cm, store, generator):
        """Full compliance report should produce valid HTML."""
        _register_full_system(cm, store)
        html = generator.compliance_report(store, "ReportTestSystem", fmt="html")
        assert "<!DOCTYPE html>" in html
        assert "ReportTestSystem" in html
        assert "HighRisk" in html

    def test_full_report_markdown(self, cm, store, generator):
        """Full compliance report should produce valid Markdown."""
        _register_full_system(cm, store)
        md = generator.compliance_report(store, "ReportTestSystem", fmt="md")
        assert "# Rapport de conformite" in md
        assert "ReportTestSystem" in md

    def test_report_with_validation(self, cm, store, generator):
        """Report with validation should include SHACL results."""
        _register_full_system(cm, store)
        validation = ValidationReport(
            conforms=False,
            violations=(
                Violation("Violation", "urn:test", "field", "Missing", "TestShape"),
            ),
            stats={"total_violations": 1, "errors": 1, "warnings": 0},
        )
        html = generator.compliance_report(
            store, "ReportTestSystem", validation=validation, fmt="html",
        )
        assert "Missing" in html

    def test_report_with_annex_iv(self, cm, store, generator):
        """Report with Annex IV should include completeness data."""
        _register_full_system(cm, store)
        annex_iv = AnnexIVReport(
            system_name="ReportTestSystem",
            completeness_pct=45.0,
            points=(
                AnnexIVPoint("1", "Description", "Annexe IV, pt. 1", 3, 2, ("field_a",)),
            ),
            missing_fields=("field_a",),
            timestamp="2026-02-19T00:00:00Z",
        )
        html = generator.compliance_report(
            store, "ReportTestSystem", annex_iv=annex_iv, fmt="html",
        )
        assert "45.0%" in html


class TestExportViaComplianceManager:
    def test_export_html(self, cm, store):
        """export_report via ComplianceManager should produce HTML."""
        _register_full_system(cm, store)
        html = cm.export_report("ReportTestSystem", fmt="html")
        assert "<!DOCTYPE html>" in html
        assert "ReportTestSystem" in html

    def test_export_md(self, cm, store):
        """export_report via ComplianceManager should produce Markdown."""
        _register_full_system(cm, store)
        md = cm.export_report("ReportTestSystem", fmt="md")
        assert "# Rapport de conformite" in md

    def test_export_without_validation(self, cm, store):
        """Export without validation should still produce a report."""
        _register_full_system(cm, store)
        html = cm.export_report(
            "ReportTestSystem",
            fmt="html",
            include_validation=False,
            include_annex_iv=False,
        )
        assert "ReportTestSystem" in html
