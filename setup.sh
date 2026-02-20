#!/usr/bin/env bash
# Agent Owl — Manual installation script
# Use this if `claude plugin install` is not available.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$HOME/.claude"

echo "=== Agent Owl — ATUM Audit Agent ==="
echo "Installing from: $SCRIPT_DIR"
echo ""

# 1. Install Python dependencies
echo "[1/5] Installing Python dependencies..."
pip install -e "$SCRIPT_DIR" 2>/dev/null || pip install rdflib watchdog
pip install "mcp[cli]" 2>/dev/null || echo "  Warning: mcp package not installed (MCP server won't work)"
echo "  Done."

# 2. Configure MCP server
echo "[2/5] Configuring MCP server..."
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
echo "[3/5] Installing hooks..."
mkdir -p "$CLAUDE_DIR/hooks"
for hook in atum-session-start.py atum-post-write.py atum-compliance-check.py; do
    cp "$SCRIPT_DIR/hooks/$hook" "$CLAUDE_DIR/hooks/$hook"
    echo "  Copied $hook"
done
echo "  Note: Add hooks to $CLAUDE_DIR/settings.local.json manually (see README)"

# 4. Install skill command
echo "[4/5] Installing skill command..."
mkdir -p "$CLAUDE_DIR/commands"
cp "$SCRIPT_DIR/commands/atum-audit.md" "$CLAUDE_DIR/commands/atum-audit.md"
echo "  Copied atum-audit.md"

# 5. Add audit_store to global gitignore
echo "[5/5] Updating global gitignore..."
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

echo ""
echo "=== Installation complete ==="
echo "Restart Claude Code to activate Agent Owl."
echo "Run: /atum-audit stats  (to verify)"
