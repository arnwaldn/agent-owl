---
description: ATUM Audit Agent — file integrity and EU AI Act compliance
argument-hint: <operation> [args] (e.g., scan, verify path/to/file, status MySystem, init, projects)
---

# ATUM Audit Agent

Run file integrity and EU AI Act compliance operations via MCP tools.
Supports multi-project operation — commands auto-detect the current project.

## Operations

Parse the user's argument to determine which operation to run:

### File Integrity

| Command | MCP Tool | Description |
|---------|----------|-------------|
| `scan` | `audit_full_scan` | Full integrity scan of all watched paths |
| `verify <filepath>` | `audit_verify_file` | Verify a single file's hash |
| `history <filepath>` | `audit_file_history` | Show audit trail for a file |
| `stats` | `audit_stats` | Show store statistics |
| `violations` | `audit_violations` | List all integrity violations |

### EU AI Act Compliance

| Command | MCP Tool | Description |
|---------|----------|-------------|
| `status <system>` | `compliance_status` | Compliance overview for an AI system |
| `validate <system>` | `compliance_validate` | SHACL validation (ontology constraints) |
| `annex-iv <system>` | `compliance_annex_iv` | Annex IV documentation completeness |
| `report <system> [html\|md]` | `compliance_export_report` | Export formatted compliance report |
| `incidents [system]` | `compliance_incidents` | List incidents (Art. 62) |
| `retention` | `compliance_retention_check` | Check log retention (Art. 12) |
| `register <name> [risk_level]` | `compliance_register_system` | Register new AI system |

### Query

| Command | MCP Tool | Description |
|---------|----------|-------------|
| `sparql "<SPARQL query>"` | `audit_sparql` | Execute read-only SPARQL query |

### Project Management

| Command | MCP Tool | Description |
|---------|----------|-------------|
| `init [path]` | `audit_init` | Initialize ATUM in a directory (default: CWD) |
| `projects` | `audit_list_projects` | List all active ATUM projects in cache |

## Instructions

1. Parse the operation from the argument string
2. Call the corresponding MCP tool from the `atum-audit` server
3. Format the result clearly for the user
4. If no argument is provided, show a summary: call `audit_stats` then display available commands
5. For project-wide commands, pass `project_path` if the user specifies one

## Examples

```
/atum-audit scan
/atum-audit verify C:\Users\arnau\Projects\myapp\src\main.py
/atum-audit status MyChatbot
/atum-audit validate MyChatbot
/atum-audit annex-iv MyChatbot
/atum-audit violations
/atum-audit sparql "SELECT ?s ?p ?o WHERE { ?s a atum:AISystem . ?s ?p ?o } LIMIT 10"
/atum-audit init C:\Users\arnau\Projects\new-app
/atum-audit projects
```
