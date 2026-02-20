#!/usr/bin/env python3
"""
ATUM Audit -- Post-Commit compliance hook for Claude Code.

Shows a brief compliance summary after every git commit.
Only triggers on Bash commands containing "git commit".

Hook type: PostToolUse, matcher: Bash
Output: stdout (displayed to user in Claude Code)
Exit code: always 0 (never blocks Claude)
"""

import json
import os
import re
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

    # Only trigger on git commit commands
    tool_input = data.get("tool_input", {})
    command = tool_input.get("command", "")
    if not re.search(r"git\s+commit", command):
        return

    # Add ATUM library to path
    lib_dir = os.environ.get("ATUM_PROJECT_DIR", _PLUGIN_DIR)
    if lib_dir and lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

    from atum_audit.discovery import find_config
    from atum_audit.agent import AuditAgent

    # Detect project from CWD (where git commit was run)
    cwd = data.get("cwd", os.getcwd())
    config_path = find_config(cwd)
    if config_path is None:
        return  # Not an ATUM project -- skip silently

    agent = AuditAgent(str(config_path))
    stats = agent.stats()
    violations = agent.violations()
    project_name = config_path.parent.name

    # Summary line
    print(
        f"[ATUM:{project_name}] Tracked: {stats.get('tracked_files', 0)} files | "
        f"Violations: {len(violations)} | "
        f"AI systems: {stats.get('ai_systems', 0)}"
    )

    # Show first few violations if any
    if violations:
        print(f"[ATUM:{project_name}] WARNING: {len(violations)} integrity violation(s)!")
        for v in violations[:3]:
            print(f"  - {v.get('path', 'unknown')}: {v.get('desc', '')}")

    # Retention check if AI systems exist
    if stats.get("ai_systems", 0) > 0:
        retention = agent.compliance.check_retention_compliance()
        if not retention["all_ok"]:
            count = len(retention["violations"])
            print(f"[ATUM:{project_name}] WARNING: {count} retention issue(s) (Art. 12)")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # Never block Claude
    sys.exit(0)
