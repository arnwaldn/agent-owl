"""Tests for Annex IV Completeness Tracker."""

import tempfile
from pathlib import Path

import pytest
from rdflib import Literal

from atum_audit.annexe_iv import (
    ANNEX_IV_REQUIREMENTS,
    AnnexIVPoint,
    AnnexIVReport,
    AnnexIVTracker,
)
from atum_audit.compliance import ComplianceManager
from atum_audit.store import ATUM, AuditStore


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
def tracker(store):
    return AnnexIVTracker(store)


def _register_system(cm, name="TestSystem"):
    return cm.register_ai_system(
        name,
        risk_level="high_risk",
        intended_purpose="Test purpose",
        description="A test system",
        retention_months=12,
    )


class TestAnnexIVRequirements:
    def test_nine_points_defined(self):
        """Annex IV should define exactly 9 points."""
        assert len(ANNEX_IV_REQUIREMENTS) == 9

    def test_all_points_have_fields(self):
        """Every point should have at least one required field."""
        for point_id, req in ANNEX_IV_REQUIREMENTS.items():
            assert "fields" in req, f"Point {point_id} has no fields"
            assert len(req["fields"]) > 0, f"Point {point_id} has empty fields"

    def test_all_points_have_labels(self):
        """Every point should have a label and article reference."""
        for _point_id, req in ANNEX_IV_REQUIREMENTS.items():
            assert "label" in req
            assert "article" in req
            assert "Annexe IV" in req["article"]

    def test_field_sources_valid(self):
        """All field sources should be known entity types."""
        valid_sources = {"AISystem", "ModelVersion", "Dataset", "ConformityAssessment"}
        for _point_id, req in ANNEX_IV_REQUIREMENTS.items():
            for field_name, source in req["fields"].items():
                assert source in valid_sources, (
                    f"Unknown source {source} for {field_name}"
                )

    def test_total_fields_count(self):
        """Total fields across all 9 points should match expected count."""
        total = sum(len(req["fields"]) for req in ANNEX_IV_REQUIREMENTS.values())
        assert total == 21  # 9 points, 21 fields total


class TestAnnexIVTracker:
    def test_completeness_zero_empty_system(self, cm, tracker):
        """Empty system should have 0% completeness (most fields are on linked entities)."""
        _register_system(cm)
        report = tracker.check_completeness("TestSystem")
        assert isinstance(report, AnnexIVReport)
        # systemDescription and intendedPurpose are set at registration
        assert report.completeness_pct < 100.0

    def test_completeness_with_description(self, cm, tracker, store):
        """System with description fields should have partial completeness."""
        sys_uri = _register_system(cm)
        # Add annexIV_generalDescription
        with store._lock:
            store._abox.add((sys_uri, ATUM.annexIV_generalDescription, Literal("Full description")))
            store._mark_dirty()
        report = tracker.check_completeness("TestSystem")
        # Point 1: systemDescription + intendedPurpose + annexIV_generalDescription
        point_1 = next(p for p in report.points if p.point_id == "1_general_description")
        assert point_1.filled_fields == 3
        assert point_1.complete is True

    def test_missing_fields_list(self, cm, tracker):
        """get_missing_fields should list all missing field names."""
        _register_system(cm)
        missing = tracker.get_missing_fields("TestSystem")
        assert isinstance(missing, list)
        assert len(missing) > 0
        assert "annexIV_generalDescription" in missing

    def test_report_frozen(self, cm, tracker):
        """AnnexIVReport should be immutable."""
        _register_system(cm)
        report = tracker.check_completeness("TestSystem")
        with pytest.raises(AttributeError):
            report.completeness_pct = 100.0

    def test_point_frozen(self):
        """AnnexIVPoint should be immutable."""
        pt = AnnexIVPoint(
            point_id="test",
            label="Test Point",
            article="Annexe IV, test",
            total_fields=3,
            filled_fields=1,
            missing=("a", "b"),
        )
        with pytest.raises(AttributeError):
            pt.filled_fields = 3

    def test_point_pct(self):
        """AnnexIVPoint.pct should compute correctly."""
        pt = AnnexIVPoint(
            point_id="test",
            label="Test",
            article="test",
            total_fields=4,
            filled_fields=3,
            missing=("a",),
        )
        assert pt.pct == 75.0

    def test_point_complete(self):
        """AnnexIVPoint.complete should be True when all fields filled."""
        pt = AnnexIVPoint(
            point_id="test",
            label="Test",
            article="test",
            total_fields=2,
            filled_fields=2,
            missing=(),
        )
        assert pt.complete is True

    def test_unknown_system(self, tracker):
        """Checking completeness for unknown system should return 0% gracefully."""
        report = tracker.check_completeness("NonexistentSystem")
        assert report.completeness_pct < 100.0
        assert len(report.missing_fields) > 0

    def test_report_has_timestamp(self, cm, tracker):
        """Report should include a timestamp."""
        _register_system(cm)
        report = tracker.check_completeness("TestSystem")
        assert report.timestamp is not None
        assert len(report.timestamp) > 0


class TestAnnexIVIntegration:
    def test_progressive_filling(self, cm, tracker, store):
        """Completeness should increase as fields are populated."""
        sys_uri = _register_system(cm)
        report_1 = tracker.check_completeness("TestSystem")
        pct_1 = report_1.completeness_pct

        # Add several annexIV fields
        with store._lock:
            store._abox.add((sys_uri, ATUM.annexIV_generalDescription, Literal("Description")))
            store._abox.add((sys_uri, ATUM.annexIV_componentDescription, Literal("Components")))
            store._abox.add((sys_uri, ATUM.annexIV_oversightMeasures, Literal("Oversight")))
            store._abox.add((sys_uri, ATUM.annexIV_cybersecurityMeasures, Literal("Security")))
            store._abox.add((sys_uri, ATUM.annexIV_foreseeMisuse, Literal("Misuse")))
            store._abox.add((sys_uri, ATUM.annexIV_developmentProcess, Literal("Process")))
            store._abox.add((sys_uri, ATUM.annexIV_hardwareRequirements, Literal("Hardware")))
            store._mark_dirty()

        report_2 = tracker.check_completeness("TestSystem")
        assert report_2.completeness_pct > pct_1

    def test_model_version_fields(self, cm, tracker, store):
        """Annex IV fields on ModelVersion should be detected."""
        sys_uri = _register_system(cm)
        mv_uri = cm.register_model_version(
            sys_uri, "v1.0.0",
            performance_metrics={"accuracy": 0.95},
            training_data="train-set",
        )

        # Add annexIV fields to model version
        with store._lock:
            store._abox.add((mv_uri, ATUM.annexIV_performanceDescription, Literal("High accuracy")))
            store._abox.add((mv_uri, ATUM.annexIV_knownLimitations, Literal("Edge cases")))
            store._abox.add((mv_uri, ATUM.annexIV_accuracyMetrics, Literal("F1=0.95")))
            store._mark_dirty()

        report = tracker.check_completeness("TestSystem")
        point_4 = next(p for p in report.points if p.point_id == "4_capabilities")
        assert point_4.filled_fields >= 2  # At least performanceDescription + knownLimitations

    def test_dataset_fields(self, cm, tracker, store):
        """Annex IV fields on Dataset should be detected via model lineage."""
        sys_uri = _register_system(cm)
        cm.register_model_version(
            sys_uri, "v1.0.0",
            training_data="train-set",
        )

        # Get dataset URI and add annexIV fields
        ds_uri = store._idx_dataset.get("train-set")
        if ds_uri:
            with store._lock:
                store._abox.add((ds_uri, ATUM.annexIV_dataGovernance, Literal("Governance policy")))
                store._abox.add((ds_uri, ATUM.annexIV_dataOrigin, Literal("Public dataset")))
                store._mark_dirty()

            report = tracker.check_completeness("TestSystem")
            point_5 = next(p for p in report.points if p.point_id == "5_data_governance")
            assert point_5.filled_fields >= 2

    def test_via_compliance_manager(self, cm, store):
        """annex_iv_status via ComplianceManager should work."""
        _register_system(cm)
        report = cm.annex_iv_status("TestSystem")
        assert isinstance(report, AnnexIVReport)
        assert report.system_name == "TestSystem"
