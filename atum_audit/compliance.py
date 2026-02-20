"""
ATUM Audit Agent — EU AI Act Compliance Manager (Reg. 2024/1689).
Facade over AuditStore for AI Act operations: system registration,
incident reporting, risk management, and compliance reporting.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from rdflib import URIRef

from ._utils import local_name
from .store import ATUM, AuditStore

if TYPE_CHECKING:
    from .annexe_iv import AnnexIVReport
    from .validator import ValidationReport

logger = logging.getLogger("atum_audit.compliance")

__all__ = ["ComplianceManager"]

# String-to-URIRef mappings for user-facing API
_RISK_LEVEL_MAP: dict[str, URIRef] = {
    "unacceptable": ATUM.Unacceptable,
    "high_risk": ATUM.HighRisk,
    "high": ATUM.HighRisk,
    "limited_risk": ATUM.LimitedRisk,
    "limited": ATUM.LimitedRisk,
    "minimal_risk": ATUM.MinimalRisk,
    "minimal": ATUM.MinimalRisk,
}

_COMPLIANCE_STATUS_MAP: dict[str, URIRef] = {
    "compliant": ATUM.Compliant,
    "non_compliant": ATUM.NonCompliant,
    "pending": ATUM.CompliancePending,
    "under_review": ATUM.UnderReview,
}

_LIFECYCLE_PHASE_MAP: dict[str, URIRef] = {
    "development": ATUM.PhaseDevelopment,
    "deployment": ATUM.PhaseDeployment,
    "operation": ATUM.PhaseOperation,
    "post_market": ATUM.PhasePostMarket,
    "retired": ATUM.PhaseRetired,
}

_INCIDENT_SEVERITY_MAP: dict[str, URIRef] = {
    "critical": ATUM.SeverityCritical,
    "high": ATUM.SeverityHigh,
    "medium": ATUM.SeverityMedium,
    "low": ATUM.SeverityLow,
}

# Art. 62: reporting deadline for serious incidents (15 days)
_INCIDENT_REPORTING_DAYS = 15
# Art. 12: minimum log retention (6 months)
_MIN_RETENTION_MONTHS = 6


def _resolve_enum(value: str, mapping: dict[str, URIRef], label: str) -> URIRef:
    """Resolve a user-friendly string to an ATUM URIRef, or raise ValueError."""
    key = value.lower().replace("-", "_").replace(" ", "_")
    result = mapping.get(key)
    if result is None:
        valid = ", ".join(sorted(mapping.keys()))
        raise ValueError(f"Invalid {label}: {value!r}. Valid values: {valid}")
    return result


class ComplianceManager:
    """
    High-level facade for EU AI Act compliance operations.

    Translates user-friendly string arguments (e.g., "high_risk") into
    ATUM namespace URIRefs and orchestrates multi-step store operations.

    Usage:
        store = AuditStore(store_dir, ontology_path)
        cm = ComplianceManager(store)
        sys_uri = cm.register_ai_system("MyModel", risk_level="high_risk")
        cm.report_incident(sys_uri, "INC-001", "Data leak detected", severity="critical")
    """

    def __init__(self, store: AuditStore):
        self._store = store
        self._shacl_validator = None  # lazy-cached

    @property
    def store(self) -> AuditStore:
        """Access the underlying AuditStore."""
        return self._store

    def register_ai_system(
        self,
        name: str,
        *,
        risk_level: str = "minimal",
        compliance_status: str = "pending",
        lifecycle_phase: str = "development",
        description: str = "",
        intended_purpose: str = "",
        provider_name: str = "",
        retention_months: int = 6,
    ) -> URIRef:
        """
        Register an AI system for compliance tracking (Art. 3).

        Args:
            name: Unique name for the AI system.
            risk_level: One of: unacceptable, high_risk, limited_risk, minimal_risk.
            compliance_status: One of: compliant, non_compliant, pending, under_review.
            lifecycle_phase: One of: development, deployment, operation, post_market, retired.
            description: Human-readable system description.
            intended_purpose: Intended purpose per Art. 3(12).
            provider_name: Provider name per Art. 3(3).
            retention_months: Log retention in months (Art. 12, min 6).

        Returns:
            URIRef of the created/existing AI system.
        """
        if not name or not name.strip():
            raise ValueError("AI system name cannot be empty")

        risk_uri = _resolve_enum(risk_level, _RISK_LEVEL_MAP, "risk_level")
        status_uri = _resolve_enum(compliance_status, _COMPLIANCE_STATUS_MAP, "compliance_status")
        phase_uri = _resolve_enum(lifecycle_phase, _LIFECYCLE_PHASE_MAP, "lifecycle_phase")

        if retention_months < _MIN_RETENTION_MONTHS:
            logger.warning(
                "Retention %d months is below Art. 12 minimum (%d). Setting to %d.",
                retention_months, _MIN_RETENTION_MONTHS, _MIN_RETENTION_MONTHS,
            )
            retention_months = _MIN_RETENTION_MONTHS

        return self._store.ensure_ai_system(
            name=name,
            risk_level=risk_uri,
            compliance_status=status_uri,
            lifecycle_phase=phase_uri,
            description=description,
            intended_purpose=intended_purpose,
            provider_name=provider_name,
            retention_months=retention_months,
        )

    def register_model_version(
        self,
        system_uri: URIRef,
        version_tag: str,
        *,
        performance_metrics: dict | None = None,
        training_data: str = "",
        validation_data: str = "",
        test_data: str = "",
    ) -> URIRef:
        """
        Register a model version with data lineage (Art. 11).

        Args:
            system_uri: URIRef of the AI system.
            version_tag: Semantic version tag (e.g., "v1.2.3").
            performance_metrics: Dict of metric name -> value (serialized as JSON).
            training_data: Name of the training dataset.
            validation_data: Name of the validation dataset.
            test_data: Name of the test dataset.

        Returns:
            URIRef of the created model version.
        """
        metrics_str = json.dumps(performance_metrics) if performance_metrics else ""

        train_uri = self._store.ensure_dataset(training_data) if training_data else None
        val_uri = self._store.ensure_dataset(validation_data) if validation_data else None
        test_uri = self._store.ensure_dataset(test_data) if test_data else None

        return self._store.record_model_version(
            system_uri=system_uri,
            version_tag=version_tag,
            performance_metrics=metrics_str,
            training_data_uri=train_uri,
            validation_data_uri=val_uri,
            test_data_uri=test_uri,
        )

    def report_incident(
        self,
        system_uri: URIRef,
        incident_id: str,
        description: str,
        *,
        severity: str = "medium",
        reporting_deadline_iso: str | None = None,
    ) -> URIRef:
        """
        Report an incident involving an AI system (Art. 62).

        If no reporting_deadline_iso is provided, it is auto-calculated
        as 15 days from now per Art. 62 requirements.

        Returns:
            URIRef of the created incident.
        """
        sev_uri = _resolve_enum(severity, _INCIDENT_SEVERITY_MAP, "severity")

        if reporting_deadline_iso is None:
            deadline = datetime.now(UTC) + timedelta(days=_INCIDENT_REPORTING_DAYS)
            reporting_deadline_iso = deadline.isoformat()

        return self._store.record_incident(
            system_uri=system_uri,
            incident_id=incident_id,
            description=description,
            severity=sev_uri,
            reporting_deadline_iso=reporting_deadline_iso,
        )

    def record_risk_with_mitigation(
        self,
        system_uri: URIRef,
        risk_id: str,
        risk_description: str,
        *,
        residual_level: str = "",
        mitigation_description: str = "",
        mitigation_status: str = "planned",
    ) -> tuple[URIRef, URIRef, URIRef | None]:
        """
        Record a risk assessment with an identified risk and optional mitigation (Art. 9).

        Returns:
            Tuple of (assessment_uri, risk_uri, mitigation_uri or None).
        """
        assessment_uri = self._store.record_risk_assessment(system_uri)
        risk_uri = self._store.record_risk(
            assessment_uri, risk_id, risk_description, residual_level,
        )

        mitigation_uri = None
        if mitigation_description:
            mitigation_uri = self._store.record_mitigation(
                risk_uri, mitigation_description, mitigation_status,
            )

        return (assessment_uri, risk_uri, mitigation_uri)

    def link_files_by_pattern(
        self, system_uri: URIRef, pattern: str, base_path: str = "",
    ) -> list[tuple[str, URIRef]]:
        """
        Link tracked files matching a glob pattern to an AI system.

        Searches the store's file index for paths matching `pattern`.
        If `base_path` is given, only files under that prefix are considered.

        Returns:
            List of (filepath, file_uri) tuples that were linked.
        """
        # Snapshot file index under lock, then use public API for mutations
        snapshot = self._store.get_tracked_files()
        linked: list[tuple[str, URIRef]] = []
        for filepath, file_uri in snapshot.items():
            if base_path and not filepath.startswith(base_path):
                continue
            if fnmatch.fnmatch(filepath, pattern):
                self._store.link_file_to_ai_system(file_uri, system_uri)
                linked.append((filepath, file_uri))
        logger.info("Linked %d files matching %r to system", len(linked), pattern)
        return linked

    def compliance_report(self, system_name: str) -> dict:
        """
        Generate a comprehensive compliance report for an AI system.

        Aggregates: system status, files, incidents, risk assessments,
        model versions, and retention compliance.

        Returns:
            Dict with keys: system, files, incidents, risks, models,
            retention_ok, summary.
        """
        system_info = self._store.get_compliance_status(system_name)
        if system_info is None:
            return {"error": f"AI system {system_name!r} not found"}

        files = self._store.get_system_files(system_name)
        incidents = self._store.get_incidents(system_name)
        risks = self._store.get_risk_assessment_report(system_name)
        models = self._store.get_model_lineage(system_name)
        retention_violations = self._store.get_retention_violations()

        # Check if this system has retention violation
        retention_ok = not any(
            v.get("name") == system_name for v in retention_violations
        )

        # Build summary
        summary = {
            "system_name": system_name,
            "risk_level": local_name(system_info.get("risk", "unknown")),
            "compliance_status": local_name(system_info.get("compliance", "unknown")),
            "lifecycle_phase": local_name(system_info.get("phase", "unknown")),
            "tracked_files": len(files),
            "total_incidents": len(incidents),
            "total_risks": len(risks),
            "model_versions": len(models),
            "retention_compliant": retention_ok,
        }

        return {
            "system": system_info,
            "files": files,
            "incidents": incidents,
            "risks": risks,
            "models": models,
            "retention_ok": retention_ok,
            "summary": summary,
        }

    def check_retention_compliance(self) -> dict:
        """
        Check all AI systems for Art. 12 retention compliance.

        Returns:
            Dict with keys: compliant (list), violations (list), all_ok (bool).
        """
        violations = self._store.get_retention_violations()
        violated_names = {v.get("name") for v in violations}
        all_names = self._store.get_ai_system_names()
        compliant = sorted(n for n in all_names if n not in violated_names)

        return {
            "compliant": compliant,
            "violations": violations,
            "all_ok": len(violations) == 0,
        }

    # ── SHACL Validation ──────────────────────────────────────────────────

    def validate_system(self, system_name: str) -> ValidationReport:
        """
        Validate an AI system's data against SHACL shapes.

        Automatically selects the validation tier (core vs high_risk)
        based on the system's risk level.

        Returns:
            ValidationReport (from validator module).

        Raises:
            ImportError: If pyshacl is not installed.
        """
        from .validator import SHACLValidator

        if self._shacl_validator is None:
            self._shacl_validator = SHACLValidator()
        return self._shacl_validator.validate_store(self._store, system_name)

    # ── Annex IV Completeness ─────────────────────────────────────────────

    def annex_iv_status(self, system_name: str) -> AnnexIVReport:
        """
        Check Annex IV documentation completeness for an AI system.

        Returns:
            AnnexIVReport (from annexe_iv module).
        """
        from .annexe_iv import AnnexIVTracker

        tracker = AnnexIVTracker(self._store)
        return tracker.check_completeness(system_name)

    # ── Report Export ─────────────────────────────────────────────────────

    def export_report(
        self,
        system_name: str,
        fmt: str = "html",
        include_validation: bool = True,
        include_annex_iv: bool = True,
    ) -> str:
        """
        Generate a full compliance report for auditors.

        Args:
            system_name: Name of the AI system.
            fmt: Output format — "html" or "md".
            include_validation: Whether to include SHACL validation results.
            include_annex_iv: Whether to include Annex IV completeness.

        Returns:
            Rendered report string (HTML or Markdown).
        """
        from .report import ReportGenerator

        validation = None
        annex_iv = None

        if include_validation:
            try:
                validation = self.validate_system(system_name)
            except ImportError:
                logger.warning("pyshacl not installed, skipping validation in report")

        if include_annex_iv:
            annex_iv = self.annex_iv_status(system_name)

        generator = ReportGenerator()
        return generator.compliance_report(
            store=self._store,
            system_name=system_name,
            validation=validation,
            annex_iv=annex_iv,
            fmt=fmt,
        )
