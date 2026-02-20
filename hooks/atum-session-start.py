#!/usr/bin/env python3
"""
ATUM Audit -- SessionStart hook for Claude Code.

Auto-detects and initializes ATUM when Claude Code starts in a project.
Outputs JSON additionalContext with ATUM status.

Hook type: SessionStart
Exit code: always 0 (never blocks Claude)
"""

import json
import os
import sys
from pathlib import Path

# Deduce plugin directory from this file's location
_PLUGIN_DIR = str(Path(__file__).resolve().parent.parent)


def main():
    # Add ATUM library to path
    lib_dir = os.environ.get("ATUM_PROJECT_DIR", _PLUGIN_DIR)
    if lib_dir and lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

    from atum_audit.discovery import find_config, find_project_root, auto_init_project

    # Detect current working directory
    cwd = os.environ.get("PWD", os.getcwd())

    # Check if already an ATUM project
    config_path = find_config(cwd)
    if config_path is not None:
        project_name = config_path.parent.name
        context = f"[ATUM] Tracking project: {project_name} ({config_path.parent})"
    else:
        # Try to find a project root and auto-init
        project_root = find_project_root(cwd)
        if project_root is not None:
            config_path = auto_init_project(project_root, lib_dir=lib_dir or None)
            project_name = project_root.name
            context = f"[ATUM] Auto-initialized in: {project_name} ({project_root})"
        else:
            # Not a project directory -- nothing to do
            context = ""

    if context:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": context,
            }
        }
        print(json.dumps(output))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # Never block Claude
    sys.exit(0)
