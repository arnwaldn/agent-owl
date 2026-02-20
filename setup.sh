#!/usr/bin/env bash
# Agent Owl — Manual installation script
# Use this if `claude plugin install` is not available.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$HOME/.claude"

echo "=== Agent Owl — ATUM Audit Agent ==="
echo "Installing from: $SCRIPT_DIR"
echo ""

# 0. Check Python version
echo "[0/6] Checking Python version..."
PYVER=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
if [ -z "$PYVER" ]; then
    echo "  ERROR: Python not found. Install Python >= 3.11"
    exit 1
fi
PYMAJOR=$(echo "$PYVER" | cut -d. -f1)
PYMINOR=$(echo "$PYVER" | cut -d. -f2)
if [ "$PYMAJOR" -lt 3 ] || ([ "$PYMAJOR" -eq 3 ] && [ "$PYMINOR" -lt 11 ]); then
    echo "  ERROR: Python >= 3.11 required. Found: $PYVER"
    exit 1
fi
echo "  Python $PYVER OK."

# 1. Install Python dependencies
echo "[1/6] Installing Python dependencies..."
pip install -e "$SCRIPT_DIR[all]" 2>/dev/null || {
    echo "  Falling back to individual installs..."
    pip install rdflib watchdog
    pip install pyshacl 2>/dev/null || echo "  Warning: pyshacl not installed (SHACL validation disabled)"
    pip install jinja2 2>/dev/null || echo "  Warning: jinja2 not installed (report export disabled)"
}
pip install "mcp[cli]" 2>/dev/null || echo "  Warning: mcp package not installed (MCP server won't work)"
echo "  Done."

# 2. Configure MCP server
echo "[2/6] Configuring MCP server..."
MCP_CONFIG="$HOME/.mcp.json"
if [ -f "$MCP_CONFIG" ]; then
    # Check if atum-audit already configured
    if python -c "import json; d=json.load(open('$MCP_CONFIG')); exit(0 if 'atum-audit' in d.get('mcpServers',{}) else 1)" 2>/dev/null; then
        echo "  MCP server already configured."
    else
        python -c "
import json
with open('$MCP_CONFIG') as f:
    cfg = json.load(f)
cfg.setdefault('mcpServers', {})['atum-audit'] = {
    'command': 'python',
    'args': ['$SCRIPT_DIR/atum_mcp_server.py'],
    'env': {'ATUM_PROJECT_DIR': '$SCRIPT_DIR'}
}
with open('$MCP_CONFIG', 'w') as f:
    json.dump(cfg, f, indent=2)
"
        echo "  Added atum-audit to $MCP_CONFIG"
    fi
else
    python -c "
import json
cfg = {'mcpServers': {'atum-audit': {
    'command': 'python',
    'args': ['$SCRIPT_DIR/atum_mcp_server.py'],
    'env': {'ATUM_PROJECT_DIR': '$SCRIPT_DIR'}
}}}
with open('$MCP_CONFIG', 'w') as f:
    json.dump(cfg, f, indent=2)
"
    echo "  Created $MCP_CONFIG"
fi

# 3. Install hooks
echo "[3/6] Installing hooks..."
mkdir -p "$CLAUDE_DIR/hooks"
for hook in atum-session-start.py atum-post-write.py atum-compliance-check.py; do
    cp "$SCRIPT_DIR/hooks/$hook" "$CLAUDE_DIR/hooks/$hook"
    echo "  Copied $hook"
done
echo ""
echo "  IMPORTANT: Register hooks in $CLAUDE_DIR/settings.local.json"
echo "  See README.md section 'Manual Hook Registration' for the JSON to add."
echo ""

# 4. Install skill command
echo "[4/6] Installing skill command..."
mkdir -p "$CLAUDE_DIR/commands"
cp "$SCRIPT_DIR/commands/atum-audit.md" "$CLAUDE_DIR/commands/atum-audit.md"
echo "  Copied atum-audit.md"

# 5. Add audit_store to global gitignore
echo "[5/6] Updating global gitignore..."
GLOBAL_GITIGNORE="$(git config --global core.excludesfile 2>/dev/null || echo "$HOME/.gitignore_global")"
if [ -f "$GLOBAL_GITIGNORE" ]; then
    if ! grep -q "audit_store/" "$GLOBAL_GITIGNORE" 2>/dev/null; then
        echo -e "\n# ATUM Audit\naudit_store/" >> "$GLOBAL_GITIGNORE"
        echo "  Added audit_store/ to $GLOBAL_GITIGNORE"
    else
        echo "  audit_store/ already in $GLOBAL_GITIGNORE"
    fi
else
    echo -e "# ATUM Audit\naudit_store/" > "$GLOBAL_GITIGNORE"
    git config --global core.excludesfile "$GLOBAL_GITIGNORE"
    echo "  Created $GLOBAL_GITIGNORE"
fi

# 6. Verify installation
echo "[6/6] Verifying installation..."
python -c "import atum_audit; print(f'  atum_audit v{atum_audit.__version__} OK')" 2>/dev/null || echo "  Warning: atum_audit import failed"
python -c "from atum_mcp_server import mcp; print(f'  MCP server OK ({len(mcp._tool_manager._tools)} tools)')" 2>/dev/null || echo "  Warning: MCP server import failed (install mcp[cli])"

echo ""
echo "=== Installation complete ==="
echo "Restart Claude Code to activate Agent Owl."
echo "Run: /atum-audit stats  (to verify)"
