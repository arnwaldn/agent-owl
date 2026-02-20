# Changelog

## [2.0.0] - 2026-02-20

### Added
- **Multi-project autonomous operation**: walk-up config discovery, auto-initialization, AgentCache (LRU, max 16 projects)
- **EU AI Act compliance** (Reg. 2024/1689): system registration (Art. 3), risk management (Art. 9), log retention (Art. 12), quality management (Art. 17), incident reporting (Art. 62), Annex IV documentation
- **SHACL validation**: core tier for all systems, high_risk tier for Art. 6 systems
- **Annex IV completeness checker**: 9 mandatory documentation points verification
- **Compliance report export**: HTML and Markdown formats with Jinja2 templates
- **MCP Server**: 15 tools via FastMCP (file integrity, compliance, SPARQL, project management)
- **Claude Code hooks**: SessionStart (auto-detect), PostToolUse Write|Edit (hash), PostToolUse Bash (compliance summary)
- **Claude Code plugin structure**: installable via `claude plugin install`
- **Skill command**: `/atum-audit` with 14 operations
- **Discovery module**: `find_config()`, `find_project_root()`, `auto_init_project()`, `AgentCache`
- **Thread-safe AgentCache**: OrderedDict LRU with double-check locking, flush-outside-lock pattern
- **Path traversal protection**: `audit_init` validates paths inside user home directory
- **166 tests**: unit + integration covering all modules

### Changed
- Agent paths resolved relative to config file directory (not CWD)
- Config uses relative paths for portability
- Hooks deduce library path from `__file__` (no hardcoded paths)
- OWL ontology extended with AI Act classes and properties

## [1.0.0] - 2026-02-17

### Added
- Core audit agent with real-time watchdog monitoring
- Streaming hash computation (SHA-256, SHA-512, BLAKE2b, dual-hash)
- OWL 2 DL ontology with W3C PROV-O alignment
- RDF graph store (rdflib) with thread-safe operations
- SPARQL query engine (read-only SELECT/CONSTRUCT)
- CLI: init, start, scan, verify, history, violations, stats, query
- File categories (code, config, spec, media, contract, invoice, deliverable)
- Periodic full scan with configurable interval
- Turtle serialization with atomic writes
