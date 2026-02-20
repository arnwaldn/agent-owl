# Agent Owl — ATUM Audit Agent v2.0

Cryptographic file integrity agent with OWL/RDF audit trail and EU AI Act (Reg. 2024/1689) compliance. Multi-project, fully autonomous — zero configuration needed.

## Architecture

```
atum_audit/
├── ontology.ttl         # OWL 2 DL ontology (TBox) — 709 triples
├── ontology-shacl.ttl   # SHACL shapes — 194 triples (core + high_risk)
├── store.py             # Thread-safe RDF store (rdflib, ReentrantLock)
├── hasher.py            # Streaming hash: SHA-256, SHA-512, BLAKE2b
├── agent.py             # Core agent: watchdog, scan, events, config resolution
├── discovery.py         # Walk-up config finder, project root detection, AgentCache
├── compliance.py        # EU AI Act engine: register, report, retention, incidents
├── validator.py         # SHACL validation (core + high_risk tiers)
├── annexe_iv.py         # Annex IV documentation completeness (9 points)
├── report.py            # HTML/Markdown report generator (Jinja2)
├── _utils.py            # Internal utilities
├── __init__.py          # Package init (v2.0.0)
├── __main__.py          # CLI entry point
└── templates/
    ├── report.html.j2   # HTML compliance report template
    └── report.md.j2     # Markdown compliance report template

atum_mcp_server.py       # FastMCP server — 15 tools, multi-project via AgentCache
hooks/                   # Claude Code hooks (SessionStart, PostWrite, PostCommit)
commands/atum-audit.md   # Skill command /atum-audit
audit_store/             # Runtime data (per-project, gitignored)
└── audit.ttl            # Accumulated RDF data (ABox)
```

## Key Design Decisions

- **Config-relative paths**: `store_path` and `watch_paths` resolve from config file directory, not CWD
- **Immutable TBox**: Ontology (ontology.ttl) is loaded once and never modified at runtime
- **Mutable ABox**: Audit data (audit.ttl) accumulates events, versions, hashes
- **Thread safety**: ReentrantLock in AuditStore, Lock + OrderedDict in AgentCache
- **Snapshot-then-flush**: Cache operations snapshot under lock, flush I/O outside lock
- **Auto-init**: Hooks detect project roots (14 markers) and initialize ATUM automatically

## MCP Tools (15)

### File integrity
- `audit_verify_file(filepath)` — verify hash
- `audit_file_history(filepath)` — audit trail
- `audit_full_scan(project_path?)` — scan all files
- `audit_stats(project_path?)` — statistics
- `audit_violations(project_path?)` — list violations

### Compliance
- `compliance_register_system(name, risk_level, ...)` — register AI system
- `compliance_status(system_name)` — compliance overview
- `compliance_validate(system_name)` — SHACL validation
- `compliance_annex_iv(system_name)` — Annex IV check
- `compliance_incidents(system_name?)` — list incidents
- `compliance_export_report(system_name, format)` — HTML/MD report

### Query
- `audit_sparql(query)` — SPARQL SELECT/CONSTRUCT
- `compliance_retention_check()` — Art. 12 retention

### Project management
- `audit_init(target_path)` — initialize ATUM
- `audit_list_projects()` — list cached projects

## CLI

```bash
atum-audit init [--path DIR]      # Initialize in directory
atum-audit start                   # Start daemon with watchdog
atum-audit scan                    # One-shot full scan
atum-audit verify PATH             # Check single file integrity
atum-audit history PATH            # Full audit trail
atum-audit violations              # List violations (exit 1 if any)
atum-audit stats                   # Summary
atum-audit query "SPARQL..."       # Arbitrary SPARQL query
```

## Programmatic Usage

```python
from atum_audit.agent import AuditAgent

agent = AuditAgent("atum-audit.config.json")
agent.full_scan()
result = agent.verify_file("src/main.py")
stats = agent.stats()
violations = agent.violations()
history = agent.history("src/main.py")
results = agent.query("SELECT ?s ?p ?o WHERE { ?s a atum:AISystem . ?s ?p ?o }")
```

## DO NOT

- Edit `ontology.ttl` or `ontology-shacl.ttl` without understanding OWL 2 DL + SHACL
- Delete `audit_store/audit.ttl` — this is the accumulated audit trail
- Disable watchdog in production
- Set scan_interval below 10 seconds
- Run SPARQL INSERT/DELETE (store is read-only via query API)
- Mutate AuditStore without acquiring the lock
