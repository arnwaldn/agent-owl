"""
ATUM Audit — Project discovery, auto-initialization, and agent caching.

Provides the walk-up config discovery (like git finds .git/) and an
agent cache for multi-project support. Used by hooks, MCP server,
and CLI to automatically detect and initialize ATUM in any project.
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .agent import AuditAgent

logger = logging.getLogger("atum_audit.discovery")

__all__ = [
    "CONFIG_FILENAME",
    "PROJECT_MARKERS",
    "find_config",
    "find_project_root",
    "auto_init_project",
    "AgentCache",
    "get_agent_for_path",
]

CONFIG_FILENAME = "atum-audit.config.json"

# Markers that indicate a project root directory.
# Ordered roughly by frequency across ecosystems.
PROJECT_MARKERS: frozenset[str] = frozenset({
    ".git",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "pubspec.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "CMakeLists.txt",
    "Makefile",
    "setup.py",
    "requirements.txt",
})


# ── Walk-up discovery ────────────────────────────────────────────────────


def find_config(start_path: str | Path) -> Path | None:
    """Walk up from *start_path* to find the nearest atum-audit.config.json.

    If *start_path* is a file, the search starts from its parent directory.
    Returns the absolute path to the config file, or ``None``.
    """
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent

    while True:
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            return None
        current = parent


def find_project_root(start_path: str | Path) -> Path | None:
    """Walk up from *start_path* to find a project root marker.

    Checks for common project root indicators (.git, package.json, etc.).
    Returns the directory containing the marker, or ``None``.
    """
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent

    while True:
        for marker in PROJECT_MARKERS:
            if (current / marker).exists():
                return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


# ── Auto-initialization ──────────────────────────────────────────────────


def _default_config() -> dict:
    """Return default ATUM config with relative paths."""
    return {
        "watch_paths": ["./"],
        "exclude_patterns": [
            "**/.git/**",
            "**/__pycache__/**",
            "**/node_modules/**",
            "**/.venv/**",
            "**/venv/**",
            "**/.DS_Store",
            "**/Thumbs.db",
            "**/*.pyc",
            "**/audit_store/**",
            "**/*.backup.*",
            "*.backup.*",
        ],
        "hash_algorithm": "sha256",
        "dual_hash": False,
        "store_path": "./audit_store",
        "ontology_file": "audit.ttl",
        "scan_interval_seconds": 300,
        "max_file_size_bytes": 524288000,
        "file_categories": {
            "code": [".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go", ".java", ".cs", ".dart", ".rb", ".php"],
            "config": [".json", ".yaml", ".yml", ".toml", ".env", ".xml"],
            "spec": [".md", ".txt", ".rst"],
            "media": [".png", ".jpg", ".jpeg", ".svg", ".webp"],
        },
        "log_level": "INFO",
        "enable_watchdog": True,
        "compact_after_events": 10000,
    }


def auto_init_project(project_root: str | Path, lib_dir: str | Path | None = None) -> Path:
    """Initialize ATUM in a project directory. Returns the config path.

    Creates ``atum-audit.config.json``, ``audit_store/``, copies the
    ontology, and updates ``.gitignore``. Safe to call if already initialized.
    """
    root = Path(project_root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    config_path = root / CONFIG_FILENAME
    if not config_path.exists():
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(_default_config(), f, indent=2)
        logger.info("Created config: %s", config_path)

    # Create audit_store/
    store_dir = root / "audit_store"
    store_dir.mkdir(exist_ok=True)

    # Copy ontology from lib if available
    if lib_dir is not None:
        onto_src = Path(lib_dir) / "atum_audit" / "ontology.ttl"
        onto_dst = store_dir / "ontology.ttl"
        if onto_src.exists() and not onto_dst.exists():
            shutil.copy(onto_src, onto_dst)

    # Update .gitignore
    _ensure_gitignore(root, "audit_store/")

    return config_path


def _ensure_gitignore(project_root: Path, entry: str) -> None:
    """Add *entry* to .gitignore if not already present."""
    gitignore = project_root / ".gitignore"
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8")
        if entry not in content:
            with open(gitignore, "a", encoding="utf-8") as f:
                f.write(f"\n# ATUM Audit\n{entry}\n")
    else:
        gitignore.write_text(f"# ATUM Audit\n{entry}\n", encoding="utf-8")


# ── Agent cache ──────────────────────────────────────────────────────────


class AgentCache:
    """Thread-safe LRU cache of AuditAgent instances keyed by config path.

    Prevents creating multiple agents for the same project and limits
    memory usage with LRU eviction. Uses OrderedDict for O(1) LRU ops.
    """

    def __init__(self, max_size: int = 16) -> None:
        self._cache: OrderedDict[Path, AuditAgent] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size

    def get_or_create(self, config_path: Path) -> AuditAgent:
        """Return cached agent or create a new one for *config_path*."""
        from .agent import AuditAgent

        resolved = config_path.resolve()
        with self._lock:
            if resolved in self._cache:
                self._cache.move_to_end(resolved)
                return self._cache[resolved]

        # Create outside lock (may be slow: loads ontology)
        agent = AuditAgent(str(resolved))

        # Collect evicted agents to flush outside the lock
        evicted_agents: list[AuditAgent] = []

        with self._lock:
            # Double-check: another thread may have inserted while we built
            if resolved in self._cache:
                self._cache.move_to_end(resolved)
                agent.flush()  # Discard the duplicate we just built
                return self._cache[resolved]

            # Evict LRU if at capacity
            while len(self._cache) >= self._max_size:
                evicted_key, evicted = self._cache.popitem(last=False)
                evicted_agents.append(evicted)
                logger.info("Evicted agent for %s", evicted_key)

            self._cache[resolved] = agent

        # Flush evicted agents outside the lock (slow I/O)
        for ev in evicted_agents:
            ev.flush()

        return agent

    def flush_all(self) -> None:
        """Flush all cached agents to disk."""
        with self._lock:
            agents = list(self._cache.values())
        for agent in agents:
            agent.flush()

    def clear(self) -> None:
        """Flush and remove all cached agents."""
        with self._lock:
            agents = list(self._cache.values())
            self._cache.clear()
        for agent in agents:
            agent.flush()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def max_size(self) -> int:
        return self._max_size

    def cached_projects(self) -> list[str]:
        """Return list of cached config paths as strings."""
        with self._lock:
            return [str(p) for p in self._cache]


# ── Convenience ──────────────────────────────────────────────────────────


def get_agent_for_path(
    filepath: str | Path,
    *,
    cache: AgentCache | None = None,
    auto_init: bool = True,
    lib_dir: str | Path | None = None,
) -> AuditAgent | None:
    """Find or create an AuditAgent for the project containing *filepath*.

    1. Walks up to find ``atum-audit.config.json``.
    2. If not found and *auto_init* is True, looks for a project root
       marker and initializes ATUM there.
    3. Returns ``None`` if the file is not inside any detectable project.
    """
    config = find_config(filepath)

    if config is None and auto_init:
        project_root = find_project_root(filepath)
        if project_root is not None:
            config = auto_init_project(project_root, lib_dir=lib_dir)
            logger.info("Auto-initialized ATUM in %s", project_root)

    if config is None:
        return None

    if cache is not None:
        return cache.get_or_create(config)

    from .agent import AuditAgent
    return AuditAgent(str(config))
