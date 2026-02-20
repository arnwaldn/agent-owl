"""Tests for EU AI Act compliance extensions (Reg. 2024/1689)."""

import json
import tempfile
from pathlib import Path

import pytest
from rdflib import RDF, Literal, Namespace
from rdflib.namespace import OWL, XSD

from atum_audit.compliance import ComplianceManager
from atum_audit.store import ATUM, AuditStore

ATUM_NS = Namespace("https://atum.dev/ontology/audit#")


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def ontology_path():
    p = Path(__file__).parent.parent / "atum_audit" / "ontology.ttl"
    if p.exists():
        return p
    p2 = Path(__file__).parent / "ontology.ttl"
    if p2.exists():
        return p2
    pytest.fail(f"ontology.ttl not found at {p} or {p2}")


@pytest.fixture
def store(tmp_dir, ontology_path):
    return AuditStore(tmp_dir / "store", ontology_path)


@pytest.fixture
def cm(store):
    return ComplianceManager(store)


# =========================================================================
# 1. Ontology structure tests (TBox)
# =========================================================================

class TestOntologyEUAI:
    """Verify the ontology contains all AI Act classes and properties."""

    def test_ai_act_classes_exist(self, store):
        """All 10 AI Act classes should be defined in the TBox."""
        expected_classes = [
            ATUM.AISystem, ATUM.Dataset, ATUM.ModelVersion,
            ATUM.ConformityAssessment, ATUM.HumanOversightAction,
            ATUM.Incident, ATUM.IncidentReport,
            ATUM.RiskAssessment, ATUM.Risk, ATUM.MitigationMeasure,
        ]
        tbox = store._tbox
        for cls in expected_classes:
            assert (cls, RDF.type, OWL.Class) in tbox, f"Missing class: {cls}"

    def test_risk_level_enum(self, store):
        """RiskLevel enum should have 4 individuals."""
        tbox = store._tbox
        expected = [ATUM.Unacceptable, ATUM.HighRisk, ATUM.LimitedRisk, ATUM.MinimalRisk]
        for ind in expected:
            assert (ind, RDF.type, ATUM.RiskLevel) in tbox, f"Missing: {ind}"

    def test_compliance_status_enum(self, store):
        """ComplianceStatus enum should have 4 individuals."""
        tbox = store._tbox
        expected = [ATUM.Compliant, ATUM.NonCompliant, ATUM.CompliancePending, ATUM.UnderReview]
        for ind in expected:
            assert (ind, RDF.type, ATUM.ComplianceStatus) in tbox, f"Missing: {ind}"

    def test_incident_severity_enum(self, store):
        """IncidentSeverity enum should have 4 individuals."""
        tbox = store._tbox
        expected = [ATUM.SeverityCritical, ATUM.SeverityHigh, ATUM.SeverityMedium, ATUM.SeverityLow]
        for ind in expected:
            assert (ind, RDF.type, ATUM.IncidentSeverity) in tbox, f"Missing: {ind}"

    def test_lifecycle_phase_enum(self, store):
        """LifecyclePhase enum should have 5 individuals."""
        tbox = store._tbox
        expected = [
            ATUM.PhaseDevelopment, ATUM.PhaseDeployment,
            ATUM.PhaseOperation, ATUM.PhasePostMarket, ATUM.PhaseRetired,
        ]
        for ind in expected:
            assert (ind, RDF.type, ATUM.LifecyclePhase) in tbox, f"Missing: {ind}"


# =========================================================================
# 2. Store AI System tests (Art. 3)
# =========================================================================

class TestStoreAISystem:
    """Test AI system CRUD operations in the store."""

    def test_ensure_ai_system_basic(self, store):
        uri = store.ensure_ai_system("TestSystem")
        assert uri is not None
        assert (uri, RDF.type, ATUM.AISystem) in store._abox

    def test_ensure_ai_system_idempotent(self, store):
        uri1 = store.ensure_ai_system("TestSystem")
        uri2 = store.ensure_ai_system("TestSystem")
        assert uri1 == uri2

    def test_ensure_ai_system_with_all_fields(self, store):
        uri = store.ensure_ai_system(
            "FullSystem",
            risk_level=ATUM.HighRisk,
            compliance_status=ATUM.Compliant,
            lifecycle_phase=ATUM.PhaseOperation,
            description="A test AI system",
            intended_purpose="Classification",
            provider_name="ACME Corp",
            retention_months=12,
        )
        g = store._abox
        assert (uri, ATUM.hasRiskLevel, ATUM.HighRisk) in g
        assert (uri, ATUM.hasComplianceStatus, ATUM.Compliant) in g
        assert (uri, ATUM.hasLifecyclePhase, ATUM.PhaseOperation) in g
        assert (uri, ATUM.systemDescription, Literal("A test AI system")) in g
        assert (uri, ATUM.intendedPurpose, Literal("Classification")) in g
        assert (uri, ATUM.providerName, Literal("ACME Corp")) in g
        assert (uri, ATUM.retentionMinMonths, Literal(12, datatype=XSD.positiveInteger)) in g

    def test_update_compliance_status(self, store):
        uri = store.ensure_ai_system("TestSystem")
        store.update_compliance_status(uri, ATUM.Compliant)
        statuses = list(store._abox.objects(uri, ATUM.hasComplianceStatus))
        assert len(statuses) == 1
        assert statuses[0] == ATUM.Compliant

    def test_update_lifecycle_phase(self, store):
        uri = store.ensure_ai_system("TestSystem")
        store.update_lifecycle_phase(uri, ATUM.PhaseDeployment)
        phases = list(store._abox.objects(uri, ATUM.hasLifecyclePhase))
        assert len(phases) == 1
        assert phases[0] == ATUM.PhaseDeployment

    def test_link_file_to_ai_system(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        file_uri = store.ensure_file("/test/model.py")
        store.link_file_to_ai_system(file_uri, sys_uri)
        assert (file_uri, ATUM.belongsToAISystem, sys_uri) in store._abox

    def test_ai_system_in_stats(self, store):
        store.ensure_ai_system("System1")
        store.ensure_ai_system("System2")
        stats = store.get_stats()
        assert stats["ai_systems"] == 2

    def test_ai_system_persistence(self, tmp_dir, ontology_path):
        store1 = AuditStore(tmp_dir / "store", ontology_path)
        uri1 = store1.ensure_ai_system("PersistTest", risk_level=ATUM.HighRisk)
        store1.flush()

        store2 = AuditStore(tmp_dir / "store", ontology_path)
        uri2 = store2.ensure_ai_system("PersistTest")
        assert uri1 == uri2
        assert store2._idx_ai_system["PersistTest"] == uri1


# =========================================================================
# 3. Store Incident tests (Art. 62)
# =========================================================================

class TestStoreIncident:
    """Test incident recording."""

    def test_record_incident(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        inc_uri = store.record_incident(
            sys_uri, "INC-001", "Test incident", severity=ATUM.SeverityHigh,
        )
        assert inc_uri is not None
        g = store._abox
        assert (inc_uri, RDF.type, ATUM.Incident) in g
        assert (inc_uri, ATUM.involvesSystem, sys_uri) in g
        assert (inc_uri, ATUM.hasIncidentSeverity, ATUM.SeverityHigh) in g

    def test_incident_idempotent(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        uri1 = store.record_incident(sys_uri, "INC-002", "First")
        uri2 = store.record_incident(sys_uri, "INC-002", "Second")
        assert uri1 == uri2

    def test_incident_with_deadline(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        inc_uri = store.record_incident(
            sys_uri, "INC-003", "Deadline test",
            reporting_deadline_iso="2025-01-15T00:00:00+00:00",
        )
        deadlines = list(store._abox.objects(inc_uri, ATUM.reportingDeadline))
        assert len(deadlines) == 1

    def test_incident_in_stats(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        store.record_incident(sys_uri, "INC-010", "Stats test")
        stats = store.get_stats()
        assert stats["incidents"] == 1

    def test_incident_index(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        uri = store.record_incident(sys_uri, "INC-IDX", "Index test")
        assert store._idx_incident["INC-IDX"] == uri

    def test_incident_persistence(self, tmp_dir, ontology_path):
        store1 = AuditStore(tmp_dir / "store", ontology_path)
        sys_uri = store1.ensure_ai_system("TestSystem")
        inc_uri = store1.record_incident(sys_uri, "INC-PERSIST", "Persist test")
        store1.flush()

        store2 = AuditStore(tmp_dir / "store", ontology_path)
        assert store2._idx_incident["INC-PERSIST"] == inc_uri


# =========================================================================
# 4. Store Risk tests (Art. 9)
# =========================================================================

class TestStoreRisk:
    """Test risk assessment and mitigation recording."""

    def test_record_risk_assessment(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        assess_uri = store.record_risk_assessment(sys_uri)
        assert assess_uri is not None
        assert (assess_uri, RDF.type, ATUM.RiskAssessment) in store._abox
        assert (sys_uri, ATUM.hasRiskAssessment, assess_uri) in store._abox

    def test_record_risk(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        assess_uri = store.record_risk_assessment(sys_uri)
        risk_uri = store.record_risk(assess_uri, "RISK-001", "Data bias", "medium")
        assert (risk_uri, RDF.type, ATUM.Risk) in store._abox
        assert (assess_uri, ATUM.identifiesRisk, risk_uri) in store._abox

    def test_risk_idempotent(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        assess_uri = store.record_risk_assessment(sys_uri)
        uri1 = store.record_risk(assess_uri, "RISK-DUP", "Dup test")
        uri2 = store.record_risk(assess_uri, "RISK-DUP", "Dup test again")
        assert uri1 == uri2

    def test_record_mitigation(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        assess_uri = store.record_risk_assessment(sys_uri)
        risk_uri = store.record_risk(assess_uri, "RISK-MIT", "Needs mitigation")
        mit_uri = store.record_mitigation(risk_uri, "Rebalance dataset", "in_progress")
        g = store._abox
        assert (mit_uri, RDF.type, ATUM.MitigationMeasure) in g
        assert (risk_uri, ATUM.hasMitigation, mit_uri) in g
        assert (mit_uri, ATUM.mitigatesRisk, risk_uri) in g

    def test_risk_in_stats(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        assess_uri = store.record_risk_assessment(sys_uri)
        store.record_risk(assess_uri, "RISK-STAT", "Stats risk")
        stats = store.get_stats()
        assert stats["risks"] == 1

    def test_risk_index(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        assess_uri = store.record_risk_assessment(sys_uri)
        uri = store.record_risk(assess_uri, "RISK-IDX", "Index risk")
        assert store._idx_risk["RISK-IDX"] == uri


# =========================================================================
# 5. Store Conformity tests (Art. 43)
# =========================================================================

class TestStoreConformity:
    """Test conformity assessment recording."""

    def test_record_conformity(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        conf_uri = store.record_conformity_assessment(sys_uri, "Jean Dupont", "Conforme")
        g = store._abox
        assert (conf_uri, RDF.type, ATUM.ConformityAssessment) in g
        assert (sys_uri, ATUM.hasConformityAssessment, conf_uri) in g
        assert (conf_uri, ATUM.assessorName, Literal("Jean Dupont")) in g

    def test_record_human_oversight(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        ov_uri = store.record_human_oversight(sys_uri, "Manual review", "Alice Martin")
        g = store._abox
        assert (ov_uri, RDF.type, ATUM.HumanOversightAction) in g
        assert (sys_uri, ATUM.hasOversightAction, ov_uri) in g
        assert (ov_uri, ATUM.oversightActor, Literal("Alice Martin")) in g

    def test_multiple_conformity_assessments(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        store.record_conformity_assessment(sys_uri, "Assessor A", "Pass")
        store.record_conformity_assessment(sys_uri, "Assessor B", "Fail")
        confs = list(store._abox.objects(sys_uri, ATUM.hasConformityAssessment))
        assert len(confs) == 2

    def test_model_version_record(self, store):
        sys_uri = store.ensure_ai_system("TestSystem")
        ds_uri = store.ensure_dataset("TrainData", "Training set", 10000)
        mv_uri = store.record_model_version(
            sys_uri, "v1.0.0",
            performance_metrics='{"accuracy": 0.95}',
            training_data_uri=ds_uri,
        )
        g = store._abox
        assert (mv_uri, RDF.type, ATUM.ModelVersion) in g
        assert (sys_uri, ATUM.hasModelVersion, mv_uri) in g
        assert (sys_uri, ATUM.currentModelVersion, mv_uri) in g
        assert (mv_uri, ATUM.hasTrainingData, ds_uri) in g


# =========================================================================
# 6. Store Retention tests (Art. 12)
# =========================================================================

class TestStoreRetention:
    """Test log retention compliance checks."""

    def test_no_violations_default(self, store):
        store.ensure_ai_system("System6Months", retention_months=6)
        violations = store.get_retention_violations()
        assert len(violations) == 0

    def test_violation_below_6_months(self, store):
        store.ensure_ai_system(
            "BadRetention",
            retention_months=3,  # bypass ComplianceManager check
        )
        violations = store.get_retention_violations()
        assert len(violations) == 1
        assert violations[0]["name"] == "BadRetention"

    def test_mixed_retention(self, store):
        store.ensure_ai_system("Good", retention_months=12)
        store.ensure_ai_system("Bad", retention_months=2)
        violations = store.get_retention_violations()
        names = [v["name"] for v in violations]
        assert "Bad" in names
        assert "Good" not in names


# =========================================================================
# 7. ComplianceManager tests (facade)
# =========================================================================

class TestComplianceManager:
    """Test the high-level ComplianceManager facade."""

    def test_register_ai_system(self, cm):
        uri = cm.register_ai_system("TestAI", risk_level="high_risk")
        assert uri is not None
        g = cm.store._abox
        assert (uri, ATUM.hasRiskLevel, ATUM.HighRisk) in g

    def test_register_invalid_risk_level(self, cm):
        with pytest.raises(ValueError, match="Invalid risk_level"):
            cm.register_ai_system("Bad", risk_level="super_risk")

    def test_register_empty_name(self, cm):
        with pytest.raises(ValueError, match="cannot be empty"):
            cm.register_ai_system("")

    def test_retention_auto_clamp(self, cm):
        uri = cm.register_ai_system("ClampTest", retention_months=2)
        g = cm.store._abox
        ret = next(g.objects(uri, ATUM.retentionMinMonths))
        assert int(ret) >= 6

    def test_report_incident_auto_deadline(self, cm):
        sys_uri = cm.register_ai_system("IncidentAI")
        inc_uri = cm.report_incident(sys_uri, "INC-AUTO", "Auto deadline", severity="critical")
        deadlines = list(cm.store._abox.objects(inc_uri, ATUM.reportingDeadline))
        assert len(deadlines) == 1
        assert (inc_uri, ATUM.hasIncidentSeverity, ATUM.SeverityCritical) in cm.store._abox

    def test_record_risk_with_mitigation(self, cm):
        sys_uri = cm.register_ai_system("RiskAI")
        assess_uri, risk_uri, mit_uri = cm.record_risk_with_mitigation(
            sys_uri, "RISK-CM", "Compliance risk",
            mitigation_description="Add monitoring",
            mitigation_status="planned",
        )
        assert assess_uri is not None
        assert risk_uri is not None
        assert mit_uri is not None

    def test_record_risk_without_mitigation(self, cm):
        sys_uri = cm.register_ai_system("RiskAI2")
        assess_uri, risk_uri, mit_uri = cm.record_risk_with_mitigation(
            sys_uri, "RISK-NOMIT", "Simple risk",
        )
        assert mit_uri is None

    def test_register_model_version(self, cm):
        sys_uri = cm.register_ai_system("ModelAI")
        mv_uri = cm.register_model_version(
            sys_uri, "v2.0.0",
            performance_metrics={"accuracy": 0.97, "f1": 0.95},
            training_data="MNIST-train",
            validation_data="MNIST-val",
        )
        assert mv_uri is not None
        g = cm.store._abox
        assert (mv_uri, ATUM.modelVersionTag, Literal("v2.0.0")) in g
        # Datasets should have been created
        assert cm.store._idx_dataset.get("MNIST-train") is not None
        assert cm.store._idx_dataset.get("MNIST-val") is not None


# =========================================================================
# 8. Compliance query tests (SPARQL)
# =========================================================================

class TestComplianceQueries:
    """Test SPARQL-based compliance queries."""

    def test_get_compliance_status(self, store):
        store.ensure_ai_system(
            "QuerySystem",
            risk_level=ATUM.HighRisk,
            description="Query test system",
        )
        result = store.get_compliance_status("QuerySystem")
        assert result is not None
        assert "risk" in result
        assert "HighRisk" in result["risk"]

    def test_get_compliance_status_not_found(self, store):
        result = store.get_compliance_status("NonExistent")
        assert result is None

    def test_get_system_files(self, store):
        sys_uri = store.ensure_ai_system("FileSystem")
        f1 = store.ensure_file("/test/model.py")
        f2 = store.ensure_file("/test/data.csv")
        store.link_file_to_ai_system(f1, sys_uri)
        store.link_file_to_ai_system(f2, sys_uri)
        files = store.get_system_files("FileSystem")
        paths = [f["path"] for f in files]
        assert "/test/model.py" in paths
        assert "/test/data.csv" in paths

    def test_get_incidents_for_system(self, store):
        sys_uri = store.ensure_ai_system("IncSystem")
        store.record_incident(sys_uri, "INC-Q1", "Query test 1", severity=ATUM.SeverityHigh)
        store.record_incident(sys_uri, "INC-Q2", "Query test 2")
        incidents = store.get_incidents("IncSystem")
        assert len(incidents) == 2
        inc_ids = [i["incId"] for i in incidents]
        assert "INC-Q1" in inc_ids
        assert "INC-Q2" in inc_ids

    def test_get_incidents_all(self, store):
        sys1 = store.ensure_ai_system("Sys1")
        sys2 = store.ensure_ai_system("Sys2")
        store.record_incident(sys1, "INC-A", "From sys1")
        store.record_incident(sys2, "INC-B", "From sys2")
        all_incidents = store.get_incidents()
        assert len(all_incidents) == 2

    def test_get_risk_assessment_report(self, store):
        sys_uri = store.ensure_ai_system("RiskQuerySys")
        assess_uri = store.record_risk_assessment(sys_uri)
        risk_uri = store.record_risk(assess_uri, "RQ-001", "Bias risk", "high")
        store.record_mitigation(risk_uri, "Debias training data", "planned")
        report = store.get_risk_assessment_report("RiskQuerySys")
        assert len(report) >= 1
        assert report[0]["riskId"] == "RQ-001"
        assert "mitDesc" in report[0]

    def test_get_model_lineage(self, store):
        sys_uri = store.ensure_ai_system("LineageSys")
        ds_uri = store.ensure_dataset("TrainSet", "Training data", 50000)
        store.record_model_version(
            sys_uri, "v1.0", training_data_uri=ds_uri,
        )
        store.record_model_version(sys_uri, "v2.0")
        lineage = store.get_model_lineage("LineageSys")
        tags = [m["tag"] for m in lineage]
        assert "v1.0" in tags
        assert "v2.0" in tags

    def test_compliance_report(self, cm):
        sys_uri = cm.register_ai_system(
            "ReportSystem", risk_level="high_risk",
            description="Report test", provider_name="TestCorp",
        )
        cm.report_incident(sys_uri, "INC-RPT", "Report incident", severity="high")
        cm.record_risk_with_mitigation(
            sys_uri, "RISK-RPT", "Report risk",
            mitigation_description="Fix it",
        )
        report = cm.compliance_report("ReportSystem")
        assert "error" not in report
        summary = report["summary"]
        assert summary["system_name"] == "ReportSystem"
        assert summary["risk_level"] == "HighRisk"
        assert summary["total_incidents"] == 1
        assert summary["total_risks"] >= 1
        assert summary["retention_compliant"] is True

    def test_check_retention_compliance(self, cm):
        cm.register_ai_system("GoodSystem", retention_months=12)
        result = cm.check_retention_compliance()
        assert result["all_ok"] is True
        assert "GoodSystem" in result["compliant"]


# =========================================================================
# 9. Agent AI system integration tests
# =========================================================================

class TestAgentAISystemIntegration:
    """Test that the AuditAgent integrates with AI system config."""

    def test_agent_without_ai_system_config(self, tmp_dir):
        """Agent should work normally without ai_system config."""
        config = {
            "watch_paths": [str(tmp_dir)],
            "store_path": str(tmp_dir / "store"),
            "hash_algorithm": "sha256",
            "exclude_patterns": ["**/store/**"],
            "log_level": "WARNING",
            "enable_watchdog": False,
            "scan_interval_seconds": 9999,
            "max_file_size_bytes": 524288000,
            "file_categories": {},
            "project_detection": "directory",
        }
        cfg_path = tmp_dir / "test-config.json"
        cfg_path.write_text(json.dumps(config))

        from atum_audit.agent import AuditAgent
        agent = AuditAgent(str(cfg_path))
        assert agent._ai_system_uri is None
        assert agent.compliance is not None

    def test_agent_with_ai_system_config(self, tmp_dir):
        """Agent should auto-create AI system from config."""
        config = {
            "watch_paths": [str(tmp_dir)],
            "store_path": str(tmp_dir / "store"),
            "hash_algorithm": "sha256",
            "exclude_patterns": ["**/store/**"],
            "log_level": "WARNING",
            "enable_watchdog": False,
            "scan_interval_seconds": 9999,
            "max_file_size_bytes": 524288000,
            "file_categories": {},
            "project_detection": "directory",
            "ai_system": {
                "name": "TestAIAgent",
                "risk_level": "high_risk",
                "description": "Test AI system from agent config",
            },
        }
        cfg_path = tmp_dir / "test-config.json"
        cfg_path.write_text(json.dumps(config))

        from atum_audit.agent import AuditAgent
        agent = AuditAgent(str(cfg_path))
        assert agent._ai_system_uri is not None
        stats = agent.stats()
        assert stats["ai_systems"] == 1

    def test_agent_scan_links_files_to_system(self, tmp_dir):
        """Files discovered during scan should be linked to the AI system."""
        proj = tmp_dir / "proj"
        proj.mkdir()
        (proj / "model.py").write_text("import torch")

        config = {
            "watch_paths": [str(tmp_dir)],
            "store_path": str(tmp_dir / "store"),
            "hash_algorithm": "sha256",
            "exclude_patterns": ["**/store/**"],
            "log_level": "WARNING",
            "enable_watchdog": False,
            "scan_interval_seconds": 9999,
            "max_file_size_bytes": 524288000,
            "file_categories": {},
            "project_detection": "directory",
            "ai_system": {
                "name": "ScanLinkAI",
                "risk_level": "minimal",
            },
        }
        cfg_path = tmp_dir / "test-config.json"
        cfg_path.write_text(json.dumps(config))

        from atum_audit.agent import AuditAgent
        agent = AuditAgent(str(cfg_path))
        agent.full_scan()

        # Verify file is linked to AI system
        files = agent._store.get_system_files("ScanLinkAI")
        assert len(files) >= 1


# =========================================================================
# 10. Verify indexes test
# =========================================================================

class TestVerifyIndexes:
    """Test that _verify_indexes catches AI Act index inconsistencies."""

    def test_verify_indexes_with_ai_entities(self, store):
        sys_uri = store.ensure_ai_system("VerifySys")
        store.ensure_dataset("VerifyDS")
        assess_uri = store.record_risk_assessment(sys_uri)
        store.record_risk(assess_uri, "RISK-VER", "Verify risk")
        store.record_incident(sys_uri, "INC-VER", "Verify incident")
        assert store._verify_indexes() is True

    def test_verify_indexes_after_flush_reload(self, tmp_dir, ontology_path):
        store1 = AuditStore(tmp_dir / "store", ontology_path)
        sys_uri = store1.ensure_ai_system("ReloadSys")
        store1.ensure_dataset("ReloadDS")
        store1.record_incident(sys_uri, "INC-RL", "Reload test")
        store1.flush()

        store2 = AuditStore(tmp_dir / "store", ontology_path)
        assert store2._verify_indexes() is True
        assert "ReloadSys" in store2._idx_ai_system
        assert "ReloadDS" in store2._idx_dataset
        assert "INC-RL" in store2._idx_incident
