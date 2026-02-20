"""
ATUM Audit — SHACL Validator.

Validates RDF data against SHACL shapes defined in ontology-shacl.ttl.
Supports two tiers:
  - "core"      : mandatory for ALL AI systems
  - "high_risk" : additionally validates Annex IV fields (Art. 6 systems)

pyshacl is an optional dependency. If not installed, validate() raises
ImportError with a clear message.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from rdflib import Graph, Namespace
from rdflib.namespace import RDF

from ._utils import local_name

if TYPE_CHECKING:
    from .store import AuditStore

logger = logging.getLogger("atum_audit.validator")

__all__ = ["SHACLValidator", "ValidationReport", "Violation"]

ATUM = Namespace("https://atum.dev/ontology/audit#")

# Shapes that have sh:targetClass are always active (Core).
# High-Risk shapes have no target — they must be explicitly linked.
_HIGH_RISK_SHAPES = {
    ATUM.AISystemHighRiskShape: ATUM.AISystem,
    ATUM.ModelVersionHighRiskShape: ATUM.ModelVersion,
    ATUM.DatasetHighRiskShape: ATUM.Dataset,
}

_SH = Namespace("http://www.w3.org/ns/shacl#")


# ── Frozen result dataclasses ──────────────────────────────────────────────

@dataclass(frozen=True)
class Violation:
    """A single SHACL validation violation."""

    severity: str
    focus_node: str
    path: str
    message: str
    source_shape: str


@dataclass(frozen=True)
class ValidationReport:
    """Result of a SHACL validation run."""

    conforms: bool
    violations: tuple[Violation, ...]
    stats: MappingProxyType[str, int]


# ── Validator class ────────────────────────────────────────────────────────

class SHACLValidator:
    """
    Validates RDF graphs against SHACL shapes.

    The shapes file is loaded once at construction time. pyshacl is
    imported lazily so the rest of ATUM works even without it.
    """

    def __init__(self, shacl_path: Path | None = None) -> None:
        if shacl_path is None:
            shacl_path = Path(__file__).parent / "ontology-shacl.ttl"
        self._shacl_path = shacl_path

        self._shapes_graph = Graph()
        if shacl_path.exists():
            self._shapes_graph.parse(str(shacl_path), format="turtle")
            logger.info("SHACL shapes loaded: %d triples", len(self._shapes_graph))
        else:
            logger.warning("SHACL shapes not found at %s", shacl_path)

    def _get_pyshacl(self):
        """Lazy import of pyshacl."""
        try:
            import pyshacl
            return pyshacl
        except ImportError as exc:
            raise ImportError(
                "pyshacl is required for SHACL validation. "
                "Install it with: pip install pyshacl>=0.26"
            ) from exc

    def _prepare_shapes(self, tier: str) -> Graph:
        """
        Prepare the shapes graph for the given tier.

        For "core", return shapes as-is (only sh:targetClass shapes apply).
        For "high_risk", add sh:targetClass to high-risk shapes so they
        also activate during validation.
        """
        if tier == "core":
            return self._shapes_graph

        # Clone the shapes graph and add targets to high-risk shapes
        extended = Graph()
        for prefix, ns in self._shapes_graph.namespaces():
            extended.bind(prefix, ns)
        for triple in self._shapes_graph:
            extended.add(triple)

        for shape_uri, target_class in _HIGH_RISK_SHAPES.items():
            extended.add((shape_uri, _SH.targetClass, target_class))

        return extended

    def validate(self, data_graph: Graph, tier: str = "core") -> ValidationReport:
        """
        Validate a data graph against SHACL shapes.

        Args:
            data_graph: The RDF graph to validate.
            tier: "core" for basic validation, "high_risk" for Annex IV.

        Returns:
            ValidationReport with conformance status and violations.
        """
        pyshacl = self._get_pyshacl()
        shapes = self._prepare_shapes(tier)

        conforms, results_graph, _results_text = pyshacl.validate(
            data_graph=data_graph,
            shacl_graph=shapes,
            inference="none",
            abort_on_first=False,
        )

        violations = self._parse_results(results_graph)

        violation_count = sum(1 for v in violations if v.severity == "Violation")
        warning_count = sum(1 for v in violations if v.severity == "Warning")

        return ValidationReport(
            conforms=conforms,
            violations=tuple(violations),
            stats=MappingProxyType({
                "total_violations": len(violations),
                "errors": violation_count,
                "warnings": warning_count,
            }),
        )

    def validate_store(
        self, store: AuditStore, system_name: str | None = None
    ) -> ValidationReport:
        """
        Validate the store's data. If system_name is provided,
        only validate data related to that system.
        """
        if system_name is not None:
            data_graph = store.export_system_graph(system_name)
        else:
            data_graph = store._get_merged_graph()

        # Determine tier from the system's risk level
        tier = "core"
        if system_name is not None:
            status = store.get_compliance_status(system_name)
            if status and local_name(status.get("risk", "")) in (
                "HighRisk", "Unacceptable",
            ):
                tier = "high_risk"

        return self.validate(data_graph, tier=tier)

    def _parse_results(self, results_graph: Graph) -> list[Violation]:
        """Parse a SHACL validation results graph into Violation objects."""
        violations: list[Violation] = []

        for result in results_graph.subjects(RDF.type, _SH.ValidationResult):
            severity_uri = results_graph.value(result, _SH.resultSeverity)
            severity = local_name(severity_uri) if severity_uri else "Violation"

            focus = results_graph.value(result, _SH.focusNode)
            focus_str = str(focus) if focus else ""

            path = results_graph.value(result, _SH.resultPath)
            path_str = local_name(path) if path else ""

            message = results_graph.value(result, _SH.resultMessage)
            message_str = str(message) if message else ""

            source = results_graph.value(result, _SH.sourceShape)
            source_str = local_name(source) if source else ""

            violations.append(Violation(
                severity=severity,
                focus_node=focus_str,
                path=path_str,
                message=message_str,
                source_shape=source_str,
            ))

        return sorted(violations, key=lambda v: (v.severity != "Violation", v.path))
