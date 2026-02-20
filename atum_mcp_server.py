#!/usr/bin/env python3
"""
ATUM Audit Agent -- MCP Server for Claude Code integration.

Exposes 15 tools for file integrity monitoring and EU AI Act compliance.
Supports multi-project operation: each tool auto-detects the correct
project from file paths or accepts an explicit project_path parameter.

Uses FastMCP with stdio transport. AuditAgent instances are lazily
initialized and cached via AgentCache (LRU, max 16 projects).
"""

import logging
import os
import sys
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from atum_audit.agent import AuditAgent

# Add project directory to sys.path for atum_audit imports
_PROJECT_DIR = Path(__file__).resolve().parent
if str(_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(_PROJECT_DIR))

from mcp.server import FastMCP

from atum_audit.discovery import (
    AgentCache,
    auto_init_project,
    find_config,
    get_agent_for_path,
)

logger = logging.getLogger("atum_mcp_server")

# ── Multi-project agent cache ──────────────────────────────────────────

_cache = AgentCache(max_size=16)
_last_used_config: Path | None = None


def _get_agent_for_file(filepath: str) -> "AuditAgent | None":
    """Auto-detect project from a file path and return its AuditAgent.

    Uses walk-up discovery to find the nearest atum-audit.config.json
    or project root, auto-initializing ATUM if needed.
    Tracks the last-used project config for default agent fallback.
    Returns None if the file is not inside any detectable project.
    """
    global _last_used_config
    agent = get_agent_for_path(
        filepath,
        cache=_cache,
        auto_init=True,
        lib_dir=str(_PROJECT_DIR),
    )
    if agent is not None:
        config = find_config(filepath)
        if config is not None:
            _last_used_config = config
    return agent


def _get_agent_for_project(project_path: str) -> "AuditAgent | None":
    """Return an AuditAgent for an explicit project directory.

    Walks up from project_path to find config, auto-inits if needed.
    """
    resolved = Path(project_path).resolve()
    return get_agent_for_path(
        resolved,
        cache=_cache,
        auto_init=True,
        lib_dir=str(_PROJECT_DIR),
    )


def _get_default_agent() -> "AuditAgent | None":
    """Return an AuditAgent using fallback detection.

    Priority: ATUM_CONFIG_PATH env var → last-used project → CWD walk-up → None.
    """
    config_env = os.environ.get("ATUM_CONFIG_PATH", "")
    if config_env:
        config_path = Path(config_env).resolve()
        if config_path.is_file():
            return _cache.get_or_create(config_path)

    # Try last-used project (tracked from file-specific tool calls)
    if _last_used_config is not None and _last_used_config.is_file():
        return _cache.get_or_create(_last_used_config)

    # Try CWD walk-up
    cwd = Path.cwd()
    return get_agent_for_path(
        cwd,
        cache=_cache,
        auto_init=False,
        lib_dir=str(_PROJECT_DIR),
    )


def _resolve_agent(project_path: str = "") -> "AuditAgent":
    """Resolve agent: explicit project_path > default fallback.

    Raises ValueError if no project can be detected.
    """
    if project_path:
        agent = _get_agent_for_project(project_path)
    else:
        agent = _get_default_agent()

    if agent is None:
        raise ValueError(
            "No ATUM project detected. Provide project_path or run "
            "'atum-audit init' in a project directory."
        )
    return agent


# ── FastMCP server ───────────────────────────────────────────────────────

mcp = FastMCP(
    "atum-audit",
    instructions=(
        "ATUM Audit Agent: cryptographic file integrity monitoring "
        "with EU AI Act (Reg. 2024/1689) compliance. "
        "Supports multi-project operation — tools auto-detect the project "
        "from file paths, or accept a project_path parameter. "
        "Tools are grouped into 4 categories: "
        "audit_* (file integrity), compliance_* (EU AI Act), "
        "query tools (SPARQL, retention), and project management."
    ),
)


# ── Serialization helpers ────────────────────────────────────────────────

def _validation_report_to_dict(report) -> dict:
    """Convert a frozen ValidationReport to a JSON-safe dict."""
    return {
        "conforms": report.conforms,
        "stats": dict(report.stats) if isinstance(report.stats, MappingProxyType) else report.stats,
        "violations": [
            {
                "severity": v.severity,
                "focus_node": v.focus_node,
                "path": v.path,
                "message": v.message,
                "source_shape": v.source_shape,
            }
            for v in report.violations
        ],
    }


def _annex_iv_report_to_dict(report) -> dict:
    """Convert a frozen AnnexIVReport to a JSON-safe dict."""
    return {
        "system_name": report.system_name,
        "completeness_pct": report.completeness_pct,
        "timestamp": report.timestamp,
        "missing_fields": list(report.missing_fields),
        "points": [
            {
                "point_id": pt.point_id,
                "label": pt.label,
                "article": pt.article,
                "total_fields": pt.total_fields,
                "filled_fields": pt.filled_fields,
                "complete": pt.complete,
                "pct": pt.pct,
                "missing": list(pt.missing),
            }
            for pt in report.points
        ],
    }


# ═════════════════════════════════════════════════════════════════════════
# FILE INTEGRITY TOOLS (5)
# ═════════════════════════════════════════════════════════════════════════


@mcp.tool(
    description="Verify cryptographic integrity of a single file against the audit store. "
    "Returns status: 'verified' (hash matches), 'VIOLATION' (hash changed), "
    "'unknown' (file not tracked), or 'error'. "
    "Auto-detects the project from the file path."
)
def audit_verify_file(filepath: str) -> dict:
    """Verify a file's integrity."""
    try:
        agent = _get_agent_for_file(filepath)
        if agent is None:
            return {"status": "unknown", "reason": "File not inside any ATUM project"}
        return agent.verify_file(filepath)
    except Exception as e:
        return {"error": str(e), "tool": "audit_verify_file"}


@mcp.tool(
    description="Get the full audit trail for a file: all events, version changes, "
    "hash history, and timestamps. Auto-detects the project from the file path."
)
def audit_file_history(filepath: str) -> list:
    """Get audit history for a file."""
    try:
        agent = _get_agent_for_file(filepath)
        if agent is None:
            return [{"info": "File not inside any ATUM project"}]
        return agent.history(filepath)
    except Exception as e:
        return [{"error": str(e), "tool": "audit_file_history"}]


@mcp.tool(
    description="Trigger a full integrity scan of all watched paths. "
    "Hashes every file, compares with stored hashes, detects new files "
    "and modifications. Returns scan statistics. "
    "Provide project_path to target a specific project."
)
def audit_full_scan(project_path: str = "") -> dict:
    """Run full integrity scan."""
    try:
        agent = _resolve_agent(project_path)
        agent.full_scan()
        agent.flush()
        return agent.stats()
    except Exception as e:
        return {"error": str(e), "tool": "audit_full_scan"}


@mcp.tool(
    description="Get audit store statistics: tracked files, versions, events, "
    "violations, AI systems, incidents, and total RDF triples. "
    "Provide project_path to target a specific project."
)
def audit_stats(project_path: str = "") -> dict:
    """Get store statistics."""
    try:
        agent = _resolve_agent(project_path)
        return agent.stats()
    except Exception as e:
        return {"error": str(e), "tool": "audit_stats"}


@mcp.tool(
    description="List all integrity violations detected in the audit store. "
    "Each violation includes the file path, expected hash, actual hash, "
    "and timestamp. Provide project_path to target a specific project."
)
def audit_violations(project_path: str = "") -> list:
    """List integrity violations."""
    try:
        agent = _resolve_agent(project_path)
        return agent.violations()
    except Exception as e:
        return [{"error": str(e), "tool": "audit_violations"}]


# ═════════════════════════════════════════════════════════════════════════
# COMPLIANCE TOOLS (6)
# ═════════════════════════════════════════════════════════════════════════


@mcp.tool(
    description="Register an AI system for EU AI Act compliance tracking (Art. 3). "
    "risk_level: unacceptable|high_risk|limited_risk|minimal_risk. "
    "compliance_status: compliant|non_compliant|pending|under_review. "
    "lifecycle_phase: development|deployment|operation|post_market|retired. "
    "Provide project_path to target a specific project."
)
def compliance_register_system(
    name: str,
    risk_level: str = "minimal",
    compliance_status: str = "pending",
    lifecycle_phase: str = "development",
    description: str = "",
    intended_purpose: str = "",
    provider_name: str = "",
    retention_months: int = 6,
    project_path: str = "",
) -> dict:
    """Register an AI system."""
    try:
        agent = _resolve_agent(project_path)
        uri = agent.compliance.register_ai_system(
            name=name,
            risk_level=risk_level,
            compliance_status=compliance_status,
            lifecycle_phase=lifecycle_phase,
            description=description,
            intended_purpose=intended_purpose,
            provider_name=provider_name,
            retention_months=retention_months,
        )
        agent.flush()
        return {"system_uri": str(uri), "name": name, "risk_level": risk_level}
    except Exception as e:
        return {"error": str(e), "tool": "compliance_register_system"}


@mcp.tool(
    description="Get a comprehensive compliance overview for a registered AI system (Art. 17). "
    "Includes: system info, tracked files, incidents, risk assessments, "
    "model versions, and retention compliance. "
    "Provide project_path to target a specific project."
)
def compliance_status(system_name: str, project_path: str = "") -> dict:
    """Get compliance report for a system."""
    try:
        agent = _resolve_agent(project_path)
        return agent.compliance.compliance_report(system_name)
    except Exception as e:
        return {"error": str(e), "tool": "compliance_status"}


@mcp.tool(
    description="Run SHACL validation against an AI system's RDF data. "
    "Checks ontology constraints (core tier for all systems, "
    "high_risk tier for Art. 6 systems with Annex IV fields). "
    "Requires pyshacl to be installed. "
    "Provide project_path to target a specific project."
)
def compliance_validate(system_name: str, project_path: str = "") -> dict:
    """Validate system with SHACL."""
    try:
        agent = _resolve_agent(project_path)
        report = agent.compliance.validate_system(system_name)
        return _validation_report_to_dict(report)
    except ImportError as e:
        return {
            "error": str(e),
            "hint": "Install pyshacl: pip install pyshacl>=0.26",
            "tool": "compliance_validate",
        }
    except Exception as e:
        return {"error": str(e), "tool": "compliance_validate"}


@mcp.tool(
    description="Check Annex IV documentation completeness for an AI system. "
    "Verifies 9 mandatory documentation points required for high-risk "
    "AI systems. Returns completeness percentage and missing fields. "
    "Provide project_path to target a specific project."
)
def compliance_annex_iv(system_name: str, project_path: str = "") -> dict:
    """Check Annex IV completeness."""
    try:
        agent = _resolve_agent(project_path)
        report = agent.compliance.annex_iv_status(system_name)
        return _annex_iv_report_to_dict(report)
    except Exception as e:
        return {"error": str(e), "tool": "compliance_annex_iv"}


@mcp.tool(
    description="List incidents involving AI systems (Art. 62). "
    "Leave system_name empty to get all incidents, or provide a name "
    "to filter by system. Provide project_path to target a specific project."
)
def compliance_incidents(system_name: str = "", project_path: str = "") -> list:
    """List incidents."""
    try:
        agent = _resolve_agent(project_path)
        name = system_name if system_name else None
        return agent.compliance.store.get_incidents(system_name=name)
    except Exception as e:
        return [{"error": str(e), "tool": "compliance_incidents"}]


@mcp.tool(
    description="Generate a formatted compliance report for auditors. "
    "Supports 'html' and 'md' formats. Includes system status, "
    "SHACL validation, Annex IV completeness, incidents, and model lineage. "
    "Provide project_path to target a specific project."
)
def compliance_export_report(
    system_name: str,
    format: str = "html",
    project_path: str = "",
) -> str:
    """Export compliance report."""
    try:
        if format not in ("html", "md"):
            return f"Invalid format '{format}'. Use 'html' or 'md'."
        agent = _resolve_agent(project_path)
        return agent.compliance.export_report(system_name, fmt=format)
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════════════════════════════
# QUERY TOOLS (2)
# ═════════════════════════════════════════════════════════════════════════


@mcp.tool(
    description="Execute a read-only SPARQL SELECT or CONSTRUCT query against "
    "the full RDF graph (TBox + ABox). Write operations are rejected. "
    "Provide project_path to target a specific project."
)
def audit_sparql(query: str, project_path: str = "") -> list:
    """Run SPARQL query."""
    try:
        agent = _resolve_agent(project_path)
        return agent.query(query)
    except Exception as e:
        return [{"error": str(e), "tool": "audit_sparql"}]


@mcp.tool(
    description="Check all AI systems for Art. 12 log retention compliance. "
    "Returns compliant systems, violations, and overall status. "
    "Provide project_path to target a specific project."
)
def compliance_retention_check(project_path: str = "") -> dict:
    """Check retention compliance."""
    try:
        agent = _resolve_agent(project_path)
        return agent.compliance.check_retention_compliance()
    except Exception as e:
        return {"error": str(e), "tool": "compliance_retention_check"}


# ═════════════════════════════════════════════════════════════════════════
# PROJECT MANAGEMENT TOOLS (2)
# ═════════════════════════════════════════════════════════════════════════


@mcp.tool(
    description="Initialize ATUM audit tracking in a project directory. "
    "Creates atum-audit.config.json, audit_store/, copies the ontology, "
    "and adds audit_store/ to .gitignore. Safe to call on already-initialized projects. "
    "Path must be inside the user's home directory."
)
def audit_init(target_path: str) -> dict:
    """Initialize ATUM in a directory."""
    try:
        resolved = Path(target_path).resolve()
        home = Path(os.path.expanduser("~")).resolve()
        try:
            resolved.relative_to(home)
        except ValueError:
            return {
                "error": f"target_path must be inside {home}. Got: {resolved}",
                "tool": "audit_init",
            }
        config_path = auto_init_project(resolved, lib_dir=str(_PROJECT_DIR))
        return {
            "status": "initialized",
            "config": str(config_path),
            "project": str(resolved),
        }
    except Exception as e:
        return {"error": str(e), "tool": "audit_init"}


@mcp.tool(
    description="List all currently cached ATUM projects. "
    "Shows which projects have active AuditAgent instances in memory."
)
def audit_list_projects() -> dict:
    """List cached projects."""
    try:
        projects = _cache.cached_projects()
        return {
            "active_projects": len(projects),
            "projects": projects,
            "max_cache_size": _cache.max_size,
        }
    except Exception as e:
        return {"error": str(e), "tool": "audit_list_projects"}


# ═════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    mcp.run(transport="stdio")
