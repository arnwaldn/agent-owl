"""
ATUM Audit — Annex IV Completeness Tracker.

Verifies that the technical documentation required by Annex IV
of Regulation (EU) 2024/1689 is complete for a given AI system.

The 9 points of Annex IV define mandatory documentation for
high-risk AI systems (Art. 6). This module checks which fields
are present in the RDF store and reports completeness.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

from rdflib import Literal

if TYPE_CHECKING:
    from .store import AuditStore

logger = logging.getLogger("atum_audit.annexe_iv")

__all__ = ["AnnexIVTracker", "AnnexIVReport", "AnnexIVPoint", "ANNEX_IV_REQUIREMENTS"]


# ── Frozen result dataclasses ──────────────────────────────────────────────

@dataclass(frozen=True)
class AnnexIVPoint:
    """Status of a single Annex IV documentation point."""

    point_id: str
    label: str
    article: str
    total_fields: int
    filled_fields: int
    missing: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return self.filled_fields == self.total_fields

    @property
    def pct(self) -> float:
        return (self.filled_fields / self.total_fields * 100.0) if self.total_fields else 100.0


@dataclass(frozen=True)
class AnnexIVReport:
    """Completeness report for Annex IV documentation."""

    system_name: str
    completeness_pct: float
    points: tuple[AnnexIVPoint, ...]
    missing_fields: tuple[str, ...]
    timestamp: str


# ── Requirements definition ───────────────────────────────────────────────


class _AnnexIVReq(TypedDict):
    label: str
    article: str
    fields: dict[str, str]  # field_name -> source class name


# Each field key = ontology property local name.
# "source" determines which SPARQL query to use for checking.

ANNEX_IV_REQUIREMENTS: dict[str, _AnnexIVReq] = {
    "1_general_description": {
        "label": "Description generale du systeme",
        "article": "Annexe IV, point 1",
        "fields": {
            "systemDescription": "AISystem",
            "intendedPurpose": "AISystem",
            "annexIV_generalDescription": "AISystem",
        },
    },
    "2_components": {
        "label": "Composants et interactions",
        "article": "Annexe IV, point 2",
        "fields": {
            "annexIV_componentDescription": "AISystem",
            "annexIV_hardwareRequirements": "AISystem",
        },
    },
    "3_development": {
        "label": "Processus de developpement",
        "article": "Annexe IV, point 3",
        "fields": {
            "annexIV_developmentProcess": "AISystem",
            "annexIV_designChoices": "ModelVersion",
            "annexIV_computationalResources": "ModelVersion",
        },
    },
    "4_capabilities": {
        "label": "Capacites et limites",
        "article": "Annexe IV, point 4",
        "fields": {
            "annexIV_performanceDescription": "ModelVersion",
            "annexIV_knownLimitations": "ModelVersion",
            "annexIV_foreseeMisuse": "AISystem",
        },
    },
    "5_data_governance": {
        "label": "Gouvernance des donnees (Art. 10)",
        "article": "Annexe IV, point 5",
        "fields": {
            "annexIV_dataGovernance": "Dataset",
            "annexIV_dataPreparation": "Dataset",
            "annexIV_dataOrigin": "Dataset",
            "annexIV_dataBiasAssessment": "Dataset",
        },
    },
    "6_human_oversight": {
        "label": "Supervision humaine (Art. 14)",
        "article": "Annexe IV, point 6",
        "fields": {
            "annexIV_oversightMeasures": "AISystem",
        },
    },
    "7_robustness": {
        "label": "Precision, robustesse, cybersecurite (Art. 15)",
        "article": "Annexe IV, point 7",
        "fields": {
            "annexIV_accuracyMetrics": "ModelVersion",
            "annexIV_robustnessTests": "ModelVersion",
            "annexIV_cybersecurityMeasures": "AISystem",
        },
    },
    "8_modifications": {
        "label": "Modifications substantielles",
        "article": "Annexe IV, point 8",
        "fields": {
            "annexIV_changeLog": "ModelVersion",
        },
    },
    "9_standards": {
        "label": "Normes harmonisees",
        "article": "Annexe IV, point 9",
        "fields": {
            "annexIV_appliedStandards": "ConformityAssessment",
        },
    },
}


# ── SPARQL batch templates ────────────────────────────────────────────────
# system_name is bound via initBindings (injection-safe).
# {values_clause} is built from static ANNEX_IV_REQUIREMENTS field names (safe).

_SPARQL_BATCH_AI_SYSTEM = """
PREFIX atum: <https://atum.dev/ontology/audit#>
SELECT DISTINCT ?prop WHERE {{
    ?sys a atum:AISystem ;
         atum:systemName ?sysname .
    ?sys ?prop ?val .
    VALUES ?prop {{ {values_clause} }}
}}
"""

_SPARQL_BATCH_MODEL_VERSION = """
PREFIX atum: <https://atum.dev/ontology/audit#>
SELECT DISTINCT ?prop WHERE {{
    ?sys a atum:AISystem ;
         atum:systemName ?sysname ;
         atum:currentModelVersion ?mv .
    ?mv ?prop ?val .
    VALUES ?prop {{ {values_clause} }}
}}
"""

_SPARQL_BATCH_DATASET = """
PREFIX atum: <https://atum.dev/ontology/audit#>
SELECT DISTINCT ?prop WHERE {{
    ?sys a atum:AISystem ;
         atum:systemName ?sysname ;
         atum:currentModelVersion ?mv .
    {{ ?mv atum:hasTrainingData ?ds }}
    UNION
    {{ ?mv atum:hasValidationData ?ds }}
    UNION
    {{ ?mv atum:hasTestData ?ds }}
    ?ds ?prop ?val .
    VALUES ?prop {{ {values_clause} }}
}}
"""

_SPARQL_BATCH_CONFORMITY = """
PREFIX atum: <https://atum.dev/ontology/audit#>
SELECT DISTINCT ?prop WHERE {{
    ?sys a atum:AISystem ;
         atum:systemName ?sysname ;
         atum:hasConformityAssessment ?ca .
    ?ca ?prop ?val .
    VALUES ?prop {{ {values_clause} }}
}}
"""

_ATUM_NS = "https://atum.dev/ontology/audit#"

_SOURCE_BATCH_SPARQL = {
    "AISystem": _SPARQL_BATCH_AI_SYSTEM,
    "ModelVersion": _SPARQL_BATCH_MODEL_VERSION,
    "Dataset": _SPARQL_BATCH_DATASET,
    "ConformityAssessment": _SPARQL_BATCH_CONFORMITY,
}


# ── Tracker class ─────────────────────────────────────────────────────────

class AnnexIVTracker:
    """Checks completeness of Annex IV documentation for an AI system."""

    def __init__(self, store: AuditStore) -> None:
        self._store = store

    def _batch_check(
        self, system_name: str, source: str, field_names: list[str],
    ) -> set[str]:
        """Check which fields exist for a source class in a single SPARQL query.

        Returns the set of field names that are populated.
        """
        template = _SOURCE_BATCH_SPARQL.get(source)
        if template is None or not field_names:
            return set()

        values = " ".join(f"atum:{f}" for f in field_names)
        query = template.format(values_clause=values)
        results = self._store.sparql(
            query, init_bindings={"sysname": Literal(system_name)}
        )

        found: set[str] = set()
        for row in results:
            prop_uri = row.get("prop", "")
            if prop_uri.startswith(_ATUM_NS):
                found.add(prop_uri[len(_ATUM_NS):])
        return found

    def check_completeness(self, system_name: str) -> AnnexIVReport:
        """Check completeness of Annex IV documentation for a system."""
        from datetime import UTC, datetime

        # Batch: group fields by source class across ALL points
        source_fields: dict[str, list[str]] = {}
        for req in ANNEX_IV_REQUIREMENTS.values():
            for field_name, source in req["fields"].items():
                source_fields.setdefault(source, []).append(field_name)

        # One SPARQL query per source class (4 max instead of N per field)
        found_fields: set[str] = set()
        for source, fields in source_fields.items():
            found_fields |= self._batch_check(system_name, source, fields)

        points: list[AnnexIVPoint] = []
        all_missing: list[str] = []
        total_fields = 0
        total_filled = 0

        for point_id, req in ANNEX_IV_REQUIREMENTS.items():
            missing: list[str] = []
            filled = 0

            for field_name in req["fields"]:
                if field_name in found_fields:
                    filled += 1
                else:
                    missing.append(field_name)

            point = AnnexIVPoint(
                point_id=point_id,
                label=req["label"],
                article=req["article"],
                total_fields=len(req["fields"]),
                filled_fields=filled,
                missing=tuple(missing),
            )
            points.append(point)
            total_fields += len(req["fields"])
            total_filled += filled
            all_missing.extend(missing)

        pct = (total_filled / total_fields * 100.0) if total_fields else 100.0

        return AnnexIVReport(
            system_name=system_name,
            completeness_pct=round(pct, 1),
            points=tuple(points),
            missing_fields=tuple(all_missing),
            timestamp=datetime.now(UTC).isoformat(),
        )

    def get_missing_fields(self, system_name: str) -> list[str]:
        """Return list of missing field names for Annex IV documentation."""
        report = self.check_completeness(system_name)
        return list(report.missing_fields)
