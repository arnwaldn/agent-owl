#!/usr/bin/env python3
"""
ATUM Audit -- Post-Write/Edit hook for Claude Code.

Automatically hashes and registers files in the audit store
after every Write or Edit operation by Claude.

Hook type: PostToolUse, matcher: Write|Edit
Exit code: always 0 (never blocks Claude)
"""

import json
import os
import sys
from pathlib import Path

# Deduce plugin directory from this file's location
_PLUGIN_DIR = str(Path(__file__).resolve().parent.parent)


def main():
    # Read tool input from stdin
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return

    # Extract file path
    tool_input = data.get("tool_input", {})
    filepath = tool_input.get("file_path", "")
    if not filepath:
        return

    fp = Path(filepath).resolve()
    if not fp.exists() or not fp.is_file():
        return

    # Skip audit store files to avoid recursion
    if "audit_store" in str(fp):
        return

    # Add ATUM library to path (for importing atum_audit package)
    lib_dir = os.environ.get("ATUM_PROJECT_DIR", _PLUGIN_DIR)
    if lib_dir and lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

    from atum_audit.discovery import get_agent_for_path

    # Auto-detect project from file path (auto-init if needed)
    agent = get_agent_for_path(fp, auto_init=True, lib_dir=lib_dir or None)
    if agent is None:
        return  # File not inside any detectable project

    agent.process_file_event(str(fp), "modified")
    agent.flush()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # Never block Claude
    sys.exit(0)
