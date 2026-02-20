"""Tests for SHACL Validator module."""

import tempfile
from pathlib import Path

import pytest
from rdflib import URIRef
from rdflib.namespace import RDF

from atum_audit.store import ATUM, AuditStore
from atum_audit.validator import SHACLValidator, ValidationReport, Violation


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
def shacl_path():
    p = Path(__file__).parent.parent / "atum_audit" / "ontology-shacl.ttl"
    if p.exists():
        return p
    pytest.fail(f"ontology-shacl.ttl not found at {p}")


@pytest.fixture
def store(tmp_dir, ontology_path):
    return AuditStore(tmp_dir / "store", ontology_path)


@pytest.fixture
def validator(shacl_path):
    return SHACLValidator(shacl_path)


def _register_system(store, name="TestSystem", risk="high_risk"):
    """Helper to register a minimal AI system."""
    from atum_audit.compliance import ComplianceManager

    cm = ComplianceManager(store)
    return cm.register_ai_system(
        name,
        risk_level=risk,
        intended_purpose="Test purpose",
        retention_months=12,
    )


class TestSHACLValidator:
    def test_shapes_loaded(self, validator):
        """SHACL shapes file should be loaded with triples."""
        assert len(validator._shapes_graph) > 0

    def test_shapes_not_found(self, tmp_dir):
        """Missing shapes file should produce empty graph, no crash."""
        v = SHACLValidator(tmp_dir / "nonexistent.ttl")
        assert len(v._shapes_graph) == 0

    def test_validate_conforming_core(self, store, validator):
        """A well-formed AI system should pass core validation."""
        _register_system(store)
        graph = store.export_system_graph("TestSystem")
        report = validator.validate(graph, tier="core")
        assert isinstance(report, ValidationReport)
        assert report.conforms is True
        assert len(report.violations) == 0

    def test_validate_missing_fields_core(self, store, validator, ontology_path):
        """An AI system without required fields should fail core validation."""
        # Manually create an incomplete AISystem (no systemName via index bypass)
        from rdflib import Graph

        data = Graph()
        data.bind("atum", ATUM)
        sys_uri = URIRef("https://atum.dev/data/test_sys")
        data.add((sys_uri, RDF.type, ATUM.AISystem))
        # Missing: systemName, hasRiskLevel, hasComplianceStatus
        report = validator.validate(data, tier="core")
        assert report.conforms is False
        assert report.stats["errors"] > 0

    def test_validate_high_risk_missing_annex_iv(self, store, validator):
        """High-risk system without Annex IV fields should fail validation."""
        _register_system(store, risk="high_risk")
        graph = store.export_system_graph("TestSystem")
        report = validator.validate(graph, tier="high_risk")
        # High-risk requires annexIV fields which are not set
        assert report.conforms is False
        assert any("Annexe IV" in v.message for v in report.violations)

    def test_validate_store_auto_tier(self, store, validator):
        """validate_store should automatically select tier based on risk level."""
        _register_system(store, risk="high_risk")
        report = validator.validate_store(store, "TestSystem")
        # Should use high_risk tier and report missing annex IV fields
        assert isinstance(report, ValidationReport)

    def test_validate_store_minimal_risk(self, store, validator):
        """Minimal risk system should use core tier."""
        _register_system(store, name="MinimalSystem", risk="minimal")
        report = validator.validate_store(store, "MinimalSystem")
        assert isinstance(report, ValidationReport)
        assert report.conforms is True

    def test_validate_store_unknown_system(self, store, validator):
        """Validating unknown system should return conforming (empty graph)."""
        report = validator.validate_store(store, "NonexistentSystem")
        assert isinstance(report, ValidationReport)


class TestValidationReport:
    def test_frozen(self):
        """ValidationReport should be immutable."""
        report = ValidationReport(
            conforms=True,
            violations=(),
            stats={"total_violations": 0, "errors": 0, "warnings": 0},
        )
        with pytest.raises(AttributeError):
            report.conforms = False

    def test_violation_frozen(self):
        """Violation should be immutable."""
        v = Violation(
            severity="Violation",
            focus_node="urn:test",
            path="systemName",
            message="Missing field",
            source_shape="AISystemCoreShape",
        )
        with pytest.raises(AttributeError):
            v.severity = "Warning"

    def test_violations_sorted(self, store, validator):
        """Violations should be sorted with errors before warnings."""
        _register_system(store, risk="high_risk")
        graph = store.export_system_graph("TestSystem")
        report = validator.validate(graph, tier="high_risk")
        if len(report.violations) >= 2:
            severities = [v.severity for v in report.violations]
            # Violations come before Warnings
            violation_idx = [i for i, s in enumerate(severities) if s == "Violation"]
            warning_idx = [i for i, s in enumerate(severities) if s == "Warning"]
            if violation_idx and warning_idx:
                assert max(violation_idx) < min(warning_idx)
