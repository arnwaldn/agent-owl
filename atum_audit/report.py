"""
ATUM Audit — Report Generator.

Generates HTML or Markdown compliance reports for auditors.
Uses Jinja2 templates with a plaintext fallback if Jinja2 is not installed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ._utils import local_name

if TYPE_CHECKING:
    from .annexe_iv import AnnexIVReport
    from .store import AuditStore
    from .validator import ValidationReport

logger = logging.getLogger("atum_audit.report")

__all__ = ["ReportGenerator"]

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """
    Generates compliance reports in HTML or Markdown format.

    Jinja2 is an optional dependency. If not installed, a basic
    plaintext fallback is used.
    """

    def __init__(self, template_dir: Path | None = None) -> None:
        self._template_dir = template_dir or _TEMPLATE_DIR
        self._jinja_env = None

    def _get_jinja_env(self):
        """Lazy-load Jinja2 environment."""
        if self._jinja_env is not None:
            return self._jinja_env

        try:
            from jinja2 import Environment, FileSystemLoader
            self._jinja_env = Environment(
                loader=FileSystemLoader(str(self._template_dir)),
                autoescape=True,
            )
            return self._jinja_env
        except ImportError:
            return None

    def generate(self, data: dict[str, Any], fmt: str = "html") -> str:
        """
        Generate a report from structured data.

        Args:
            data: Report data dictionary.
            fmt: Output format — "html" or "md".

        Returns:
            Rendered report string.
        """
        env = self._get_jinja_env()
        template_file = f"report.{fmt}.j2"

        if env is not None:
            try:
                template = env.get_template(template_file)
                return template.render(**data)
            except Exception:
                logger.warning(
                    "Template rendering failed, falling back to plaintext",
                    exc_info=True,
                )

        return self._plaintext_fallback(data)

    def compliance_report(
        self,
        store: AuditStore,
        system_name: str,
        validation: ValidationReport | None = None,
        annex_iv: AnnexIVReport | None = None,
        fmt: str = "html",
    ) -> str:
        """
        Generate a full compliance report for a given AI system.

        Args:
            store: The audit store to query.
            system_name: Name of the AI system.
            validation: Optional pre-computed SHACL validation report.
            annex_iv: Optional pre-computed Annex IV report.
            fmt: Output format — "html" or "md".

        Returns:
            Rendered report string.
        """
        from . import __version__

        # Get system status
        status = store.get_compliance_status(system_name) or {}
        incidents = store.get_incidents(system_name=system_name)
        models = store.get_model_lineage(system_name)

        data: dict[str, Any] = {
            "system_name": system_name,
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "version": __version__,
            "risk_level": local_name(status.get("risk", "Unknown")),
            "compliance_status": local_name(status.get("compliance", "Unknown")),
            "lifecycle_phase": local_name(status.get("phase", "Unknown")),
            "validation": _validation_to_dict(validation) if validation else None,
            "annex_iv": _annex_iv_to_dict(annex_iv) if annex_iv else None,
            "violations": _violations_to_list(validation) if validation else [],
            "incidents": _incidents_to_list(incidents),
            "models": _models_to_list(models),
        }

        return self.generate(data, fmt=fmt)

    def _plaintext_fallback(self, data: dict[str, Any]) -> str:
        """Generate a basic plaintext report when Jinja2 is not available."""
        lines = [
            "=== Rapport de conformite AI Act ===",
            f"Systeme : {data.get('system_name', 'N/A')}",
            f"Date    : {data.get('timestamp', 'N/A')}",
            f"Risque  : {data.get('risk_level', 'N/A')}",
            f"Statut  : {data.get('compliance_status', 'N/A')}",
            f"Phase   : {data.get('lifecycle_phase', 'N/A')}",
            "",
        ]

        validation = data.get("validation")
        if validation:
            lines.append(f"SHACL : {'Conforme' if validation.get('conforms') else 'Non conforme'}")
            lines.append(f"  Erreurs: {validation['stats'].get('errors', 0)}")
            lines.append(f"  Avertissements: {validation['stats'].get('warnings', 0)}")
            lines.append("")

        annex_iv = data.get("annex_iv")
        if annex_iv:
            lines.append(f"Annexe IV : {annex_iv.get('completeness_pct', 0)}% complete")
            for pt in annex_iv.get("points", []):
                status_mark = "[OK]" if not pt.get("missing") else "[!!]"
                lines.append(f"  {status_mark} {pt['label']} ({pt['pct']}%)")
            lines.append("")

        violations = data.get("violations", [])
        if violations:
            lines.append(f"Violations ({len(violations)}):")
            for v in violations:
                lines.append(f"  [{v['severity']}] {v['path']}: {v['message']}")
            lines.append("")

        lines.append("--- ATUM Audit Agent ---")
        return "\n".join(lines)


# ── Helper converters ─────────────────────────────────────────────────────

def _validation_to_dict(report: ValidationReport) -> dict[str, Any]:
    return {
        "conforms": report.conforms,
        "stats": dict(report.stats),
    }


def _annex_iv_to_dict(report: AnnexIVReport) -> dict[str, Any]:
    return {
        "completeness_pct": report.completeness_pct,
        "points": [
            {
                "label": pt.label,
                "article": pt.article,
                "pct": pt.pct,
                "missing": list(pt.missing),
            }
            for pt in report.points
        ],
    }


def _violations_to_list(report: ValidationReport | None) -> list[dict[str, str]]:
    if report is None:
        return []
    return [
        {
            "severity": v.severity,
            "focus_node": v.focus_node,
            "path": v.path,
            "message": v.message,
        }
        for v in report.violations
    ]


def _incidents_to_list(incidents: list[dict]) -> list[dict[str, str]]:
    return [
        {
            "incident_id": inc.get("incId", ""),
            "description": inc.get("desc", ""),
            "severity": local_name(inc.get("severity", "")),
            "timestamp": inc.get("timestamp", ""),
            "deadline": inc.get("deadline", ""),
        }
        for inc in incidents
    ]


def _models_to_list(models: list[dict]) -> list[dict[str, str]]:
    return [
        {
            "version_tag": m.get("tag", ""),
            "trained_at": m.get("trainedAt", ""),
            "metrics": m.get("metrics", ""),
        }
        for m in models
    ]
