# Agent Owl

**ATUM Audit Agent** — Cryptographic file integrity monitoring with OWL/RDF ontology and EU AI Act compliance for Claude Code.

> Every file Claude touches gets a cryptographic fingerprint. Every change becomes an immutable RDF triple. Every AI system gets EU regulation tracking. Zero configuration required.

---

## Features

### File Integrity
- **Cryptographic hashing**: SHA-256, SHA-512, BLAKE2b (single or dual-hash mode)
- **Real-time monitoring**: Watchdog-based file system events
- **Integrity verification**: Compare stored hashes against current files
- **Full audit trail**: Every version, every change, timestamped and immutable

### Semantic Knowledge Graph
- **OWL 2 DL ontology**: Formal class hierarchy with property restrictions
- **RDF triple store**: rdflib-based with thread-safe operations
- **SPARQL queries**: Read-only SELECT/CONSTRUCT against the full graph
- **W3C PROV-O alignment**: Standards-compliant provenance tracking
- **Turtle serialization**: Human-readable, compact format

### EU AI Act Compliance (Reg. 2024/1689)
- **AI system registration** (Art. 3): Risk levels, lifecycle phases, compliance status
- **Risk management** (Art. 9): Risk assessments with severity and likelihood
- **Log retention** (Art. 12): Automated retention compliance monitoring
- **Quality management** (Art. 17): Comprehensive compliance reports
- **Incident reporting** (Art. 62): Incident tracking with affected systems
- **Annex IV documentation**: 9 mandatory points completeness checker
- **SHACL validation**: Core tier + high-risk tier constraint checking

### Claude Code Integration
- **15 MCP tools**: File integrity, compliance, SPARQL, project management
- **3 automatic hooks**: SessionStart, PostWrite, PostBash (git commit) — zero configuration
- **Skill command**: `/atum-audit` with 15 operations
- **Multi-project**: Autonomous detection and tracking across all your projects
- **Plugin format**: One-command installation

---

## Architecture

```
agent-owl/
├── atum_audit/                 # Core Python library
│   ├── ontology.ttl            # OWL 2 DL ontology (TBox) — 709 triples
│   ├── ontology-shacl.ttl      # SHACL shapes — 194 triples
│   ├── store.py                # Thread-safe RDF graph store
│   ├── hasher.py               # Streaming hash computation
│   ├── agent.py                # Core agent (watchdog, scan, events)
│   ├── discovery.py            # Multi-project discovery + AgentCache
│   ├── compliance.py           # EU AI Act compliance engine
│   ├── validator.py            # SHACL validation
│   ├── annexe_iv.py            # Annex IV completeness checker
│   ├── report.py               # HTML/Markdown report generator
│   └── templates/              # Jinja2 report templates
├── atum_mcp_server.py          # FastMCP server (15 tools)
├── hooks/                      # Claude Code hooks
│   ├── atum-session-start.py   # Auto-detect project at startup
│   ├── atum-post-write.py      # Hash files on Write/Edit
│   └── atum-compliance-check.py # Compliance summary on git commit
├── commands/
│   └── atum-audit.md           # /atum-audit skill command
└── tests/                      # 166 tests
```

### How it works

```
Claude writes a file
        │
        ▼
  PostWrite hook ──────► auto-detect project (walk-up)
        │                       │
        │               auto-init if needed
        │                       │
        ▼                       ▼
  SHA-256 hash ◄──── AuditAgent instance (cached)
        │
        ▼
  RDF triple store ──► audit_store/audit.ttl
        │
        ▼
  OWL ontology ──────► SPARQL queryable
```

---

## Installation

### Claude Code Plugin (recommended)

```bash
claude plugin install github:arnwaldn/agent-owl
```

### Manual Installation

```bash
git clone https://github.com/arnwaldn/agent-owl.git
cd agent-owl
bash setup.sh
```

### Python Dependencies

```bash
pip install -e .                    # Core (rdflib, watchdog)
pip install -e ".[shacl]"          # + SHACL validation (pyshacl)
pip install -e ".[report]"         # + Report generation (jinja2)
pip install -e ".[all]"            # Everything
pip install -e ".[dev]"            # Development (pytest, ruff, mypy)
```

The MCP server requires FastMCP:
```bash
pip install -e ".[server]"         # MCP server (FastMCP)
pip install -e ".[all]"            # Everything including MCP server
```

---

## Quick Start

After installation, Agent Owl works automatically:

1. **Start Claude Code** in any project directory
2. The SessionStart hook auto-detects and initializes ATUM
3. Every file Write/Edit gets hashed and tracked
4. Every git commit shows a compliance summary

### Verify installation

```
/atum-audit stats
```

### Register an AI system for EU AI Act tracking

```
/atum-audit register MyChatbot high_risk
```

### Check compliance

```
/atum-audit status MyChatbot
/atum-audit validate MyChatbot
/atum-audit annex-iv MyChatbot
```

---

## MCP Tools Reference

### File Integrity (5 tools)

| Tool | Description |
|------|-------------|
| `audit_verify_file` | Verify cryptographic integrity of a single file |
| `audit_file_history` | Get full audit trail for a file |
| `audit_full_scan` | Scan all watched paths, detect changes |
| `audit_stats` | Store statistics (files, versions, events, triples) |
| `audit_violations` | List all integrity violations |

### EU AI Act Compliance (6 tools)

| Tool | Description |
|------|-------------|
| `compliance_register_system` | Register an AI system (Art. 3) |
| `compliance_status` | Comprehensive compliance overview (Art. 17) |
| `compliance_validate` | SHACL validation against ontology constraints |
| `compliance_annex_iv` | Annex IV documentation completeness |
| `compliance_incidents` | List incidents (Art. 62) |
| `compliance_export_report` | Export HTML/Markdown compliance report |

### Query (2 tools)

| Tool | Description |
|------|-------------|
| `audit_sparql` | Execute read-only SPARQL query |
| `compliance_retention_check` | Check Art. 12 log retention compliance |

### Project Management (2 tools)

| Tool | Description |
|------|-------------|
| `audit_init` | Initialize ATUM in a directory |
| `audit_list_projects` | List all active ATUM projects |

---

## Hooks

Agent Owl installs 3 automatic hooks in Claude Code:

| Hook | Trigger | Action |
|------|---------|--------|
| **SessionStart** | Claude Code starts | Auto-detect project, auto-init if needed |
| **PostToolUse Write\|Edit** | Any file write | Hash file and record in audit store |
| **PostToolUse Bash** | git commit | Show compliance summary |

All hooks exit 0 unconditionally — they never block Claude Code.

### Manual Hook Registration

If you installed manually (not via `claude plugin install`), add this to `~/.claude/settings.local.json`:

```json
{
  "hooks": {
    "SessionStart": [{
      "hooks": [{
        "type": "command",
        "command": "python \"$HOME/.claude/hooks/atum-session-start.py\"",
        "timeout": 15
      }]
    }],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "python \"$HOME/.claude/hooks/atum-post-write.py\"",
          "timeout": 10
        }]
      },
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "python \"$HOME/.claude/hooks/atum-compliance-check.py\"",
          "timeout": 15
        }]
      }
    ]
  }
}
```

---

## Configuration

Each project gets an `atum-audit.config.json`:

```json
{
  "watch_paths": ["./"],
  "exclude_patterns": [
    "**/.git/**", "**/__pycache__/**", "**/node_modules/**",
    "**/.venv/**", "**/venv/**", "**/.DS_Store", "**/Thumbs.db",
    "**/*.pyc", "**/audit_store/**", "**/*.backup.*", "*.backup.*"
  ],
  "hash_algorithm": "sha256",
  "dual_hash": false,
  "store_path": "./audit_store",
  "scan_interval_seconds": 300,
  "max_file_size_bytes": 524288000,
  "file_categories": {
    "code": [".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go"],
    "config": [".json", ".yaml", ".yml", ".toml", ".env"],
    "spec": [".md", ".txt", ".rst"],
    "media": [".png", ".jpg", ".jpeg", ".svg", ".webp"]
  },
  "log_level": "INFO",
  "enable_watchdog": true,
  "compact_after_events": 10000
}
```

---

## SPARQL Examples

**All files modified in last 24h:**
```sparql
PREFIX atum: <https://atum.dev/ontology/audit#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?path ?ts WHERE {
    ?evt atum:hasEventType atum:FileModified ;
         atum:concernsFile ?f ;
         atum:timestamp ?ts .
    ?f atum:filePath ?path .
    FILTER(?ts > "2026-02-19T00:00:00Z"^^xsd:dateTime)
}
```

**Full provenance chain for a file:**
```sparql
PREFIX atum: <https://atum.dev/ontology/audit#>
SELECT ?vnum ?hash ?ts WHERE {
    ?f atum:filePath "/path/to/file" ;
       atum:hasVersion ?v .
    ?v atum:versionNumber ?vnum ;
       atum:versionTimestamp ?ts ;
       atum:hasHash ?h .
    ?h atum:hashValue ?hash .
}
ORDER BY ?vnum
```

**All registered AI systems:**
```sparql
PREFIX atum: <https://atum.dev/ontology/audit#>
SELECT ?name ?risk ?status WHERE {
    ?sys a atum:AISystem ;
         atum:systemName ?name ;
         atum:hasRiskLevel ?risk ;
         atum:hasComplianceStatus ?status .
}
```

---

## Development

### Run tests

```bash
pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

### Lint

```bash
ruff check atum_audit/ atum_mcp_server.py
mypy atum_audit/
```

### Test coverage

```bash
pytest tests/ --cov=atum_audit --cov-report=term-missing
```

---

## How Multi-Project Works

Agent Owl handles multiple projects simultaneously:

1. **Walk-up discovery**: From any file path, walks up directories to find `atum-audit.config.json`
2. **Project root detection**: Recognizes 15 project markers (`.git`, `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pubspec.yaml`, `pom.xml`, `build.gradle`, `composer.json`, `Gemfile`, `CMakeLists.txt`, `Makefile`, `setup.py`, `requirements.txt`)
3. **Auto-initialization**: Creates config + audit_store + .gitignore entry automatically
4. **AgentCache**: Thread-safe LRU cache (max 16 projects) with OrderedDict for O(1) operations
5. **Isolation**: Each project has its own audit store, config, and RDF graph

---

## Tech Stack

- **Python** >= 3.11
- **rdflib** >= 7.0 — RDF/OWL graph engine
- **watchdog** >= 4.0 — File system monitoring
- **pyshacl** >= 0.26 — SHACL constraint validation (optional)
- **jinja2** >= 3.1 — Report template rendering (optional)
- **FastMCP** — Model Context Protocol server

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Agent Owl watches over your code. Every byte accounted for.*
