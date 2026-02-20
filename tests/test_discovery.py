"""Tests for atum_audit.discovery module."""

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from atum_audit.discovery import (
    CONFIG_FILENAME,
    AgentCache,
    auto_init_project,
    find_config,
    find_project_root,
    get_agent_for_path,
)


# ── find_config ──────────────────────────────────────────────────────────


class TestFindConfig:
    """Walk-up search for atum-audit.config.json."""

    def test_finds_config_in_same_dir(self, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        assert find_config(tmp_path) == config

    def test_walks_up_from_subdir(self, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        subdir = tmp_path / "src" / "components"
        subdir.mkdir(parents=True)
        assert find_config(subdir) == config

    def test_walks_up_from_file(self, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        f = tmp_path / "src" / "main.py"
        f.parent.mkdir(parents=True)
        f.write_text("pass", encoding="utf-8")
        assert find_config(f) == config

    def test_returns_none_when_not_found(self, tmp_path: Path):
        assert find_config(tmp_path) is None

    def test_finds_nearest_config_in_nested_projects(self, tmp_path: Path):
        # Outer config
        outer_config = tmp_path / CONFIG_FILENAME
        outer_config.write_text("{}", encoding="utf-8")
        # Inner config (should be found first)
        inner = tmp_path / "packages" / "core"
        inner.mkdir(parents=True)
        inner_config = inner / CONFIG_FILENAME
        inner_config.write_text("{}", encoding="utf-8")
        assert find_config(inner) == inner_config


# ── find_project_root ────────────────────────────────────────────────────


class TestFindProjectRoot:
    """Walk-up search for project root markers."""

    @pytest.mark.parametrize("marker", [".git", "package.json", "pyproject.toml", "go.mod", "Cargo.toml"])
    def test_finds_root_by_marker(self, tmp_path: Path, marker: str):
        marker_path = tmp_path / marker
        if marker == ".git":
            marker_path.mkdir()
        else:
            marker_path.write_text("", encoding="utf-8")
        subdir = tmp_path / "src"
        subdir.mkdir()
        assert find_project_root(subdir) == tmp_path

    def test_returns_none_when_no_marker(self, tmp_path: Path):
        subdir = tmp_path / "random" / "dir"
        subdir.mkdir(parents=True)
        assert find_project_root(subdir) is None

    def test_finds_nearest_root(self, tmp_path: Path):
        # Outer: .git
        (tmp_path / ".git").mkdir()
        # Inner: package.json (monorepo package)
        inner = tmp_path / "packages" / "web"
        inner.mkdir(parents=True)
        (inner / "package.json").write_text("{}", encoding="utf-8")
        assert find_project_root(inner) == inner


# ── auto_init_project ────────────────────────────────────────────────────


class TestAutoInitProject:
    """Auto-initialization of ATUM in a project directory."""

    def test_creates_config_and_store(self, tmp_path: Path):
        config_path = auto_init_project(tmp_path)
        assert config_path == tmp_path / CONFIG_FILENAME
        assert config_path.is_file()
        assert (tmp_path / "audit_store").is_dir()

    def test_config_has_relative_paths(self, tmp_path: Path):
        auto_init_project(tmp_path)
        config = json.loads((tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8"))
        assert config["watch_paths"] == ["./"]
        assert config["store_path"] == "./audit_store"

    def test_creates_gitignore_if_missing(self, tmp_path: Path):
        auto_init_project(tmp_path)
        gitignore = tmp_path / ".gitignore"
        assert gitignore.is_file()
        assert "audit_store/" in gitignore.read_text(encoding="utf-8")

    def test_appends_to_existing_gitignore(self, tmp_path: Path):
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n", encoding="utf-8")
        auto_init_project(tmp_path)
        content = gitignore.read_text(encoding="utf-8")
        assert "node_modules/" in content
        assert "audit_store/" in content

    def test_does_not_duplicate_gitignore_entry(self, tmp_path: Path):
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("audit_store/\n", encoding="utf-8")
        auto_init_project(tmp_path)
        content = gitignore.read_text(encoding="utf-8")
        assert content.count("audit_store/") == 1

    def test_idempotent_on_existing_project(self, tmp_path: Path):
        auto_init_project(tmp_path)
        config1 = (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")
        auto_init_project(tmp_path)
        config2 = (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")
        assert config1 == config2

    def test_copies_ontology_if_available(self, tmp_path: Path):
        # Create a fake lib_dir with ontology
        lib_dir = tmp_path / "lib"
        onto_dir = lib_dir / "atum_audit"
        onto_dir.mkdir(parents=True)
        (onto_dir / "ontology.ttl").write_text("@prefix : <test> .", encoding="utf-8")
        project = tmp_path / "myproject"
        project.mkdir()
        auto_init_project(project, lib_dir=str(lib_dir))
        assert (project / "audit_store" / "ontology.ttl").is_file()


# ── AgentCache ───────────────────────────────────────────────────────────


class TestAgentCache:
    """Thread-safe LRU cache for AuditAgent instances."""

    @patch("atum_audit.agent.AuditAgent.__init__", return_value=None)
    def test_returns_same_agent_for_same_config(self, mock_init, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        cache = AgentCache(max_size=4)
        a1 = cache.get_or_create(config)
        a2 = cache.get_or_create(config)
        assert a1 is a2
        assert mock_init.call_count == 1

    @patch("atum_audit.agent.AuditAgent.__init__", return_value=None)
    def test_different_configs_get_different_agents(self, mock_init, tmp_path: Path):
        c1 = tmp_path / "proj_a" / CONFIG_FILENAME
        c2 = tmp_path / "proj_b" / CONFIG_FILENAME
        c1.parent.mkdir()
        c2.parent.mkdir()
        c1.write_text("{}", encoding="utf-8")
        c2.write_text("{}", encoding="utf-8")
        cache = AgentCache(max_size=4)
        a1 = cache.get_or_create(c1)
        a2 = cache.get_or_create(c2)
        assert a1 is not a2
        assert mock_init.call_count == 2

    @patch("atum_audit.agent.AuditAgent.__init__", return_value=None)
    @patch("atum_audit.agent.AuditAgent.flush", create=True)
    def test_lru_eviction(self, mock_flush, mock_init, tmp_path: Path):
        cache = AgentCache(max_size=2)
        configs = []
        for i in range(3):
            c = tmp_path / f"proj_{i}" / CONFIG_FILENAME
            c.parent.mkdir()
            c.write_text("{}", encoding="utf-8")
            configs.append(c)

        cache.get_or_create(configs[0])
        cache.get_or_create(configs[1])
        assert cache.size == 2

        # Adding a 3rd should evict the LRU (configs[0])
        cache.get_or_create(configs[2])
        assert cache.size == 2
        projects = cache.cached_projects()
        assert str(configs[0].resolve()) not in projects
        assert str(configs[2].resolve()) in projects

    @patch("atum_audit.agent.AuditAgent.__init__", return_value=None)
    def test_flush_all(self, mock_init, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        cache = AgentCache(max_size=4)
        agent = cache.get_or_create(config)
        agent.flush = MagicMock()
        cache.flush_all()
        agent.flush.assert_called_once()

    @patch("atum_audit.agent.AuditAgent.__init__", return_value=None)
    def test_clear(self, mock_init, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        cache = AgentCache(max_size=4)
        agent = cache.get_or_create(config)
        agent.flush = MagicMock()
        assert cache.size == 1
        cache.clear()
        assert cache.size == 0

    @patch("atum_audit.agent.AuditAgent.__init__", return_value=None)
    def test_concurrent_get_or_create_returns_same_agent(self, mock_init, tmp_path: Path):
        config = tmp_path / CONFIG_FILENAME
        config.write_text("{}", encoding="utf-8")
        cache = AgentCache(max_size=4)
        results: list[object] = []

        def worker():
            results.append(cache.get_or_create(config))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads must get the same single agent instance
        unique_ids = set(id(r) for r in results)
        assert len(unique_ids) == 1


# ── get_agent_for_path ───────────────────────────────────────────────────


class TestGetAgentForPath:
    """Convenience function combining walk-up + auto-init + cache."""

    def test_returns_none_for_path_outside_project(self, tmp_path: Path):
        isolated = tmp_path / "no_project_here"
        isolated.mkdir()
        agent = get_agent_for_path(isolated, auto_init=False)
        assert agent is None

    def test_auto_init_creates_config_and_returns_agent(self, tmp_path: Path):
        # Create a project root marker
        (tmp_path / ".git").mkdir()
        subfile = tmp_path / "src" / "app.py"
        subfile.parent.mkdir()
        subfile.write_text("pass", encoding="utf-8")
        agent = get_agent_for_path(subfile, auto_init=True)
        assert agent is not None
        assert (tmp_path / CONFIG_FILENAME).is_file()
        assert (tmp_path / "audit_store").is_dir()

    def test_finds_existing_config(self, tmp_path: Path):
        # Manually create a config
        config = tmp_path / CONFIG_FILENAME
        config.write_text(json.dumps({
            "watch_paths": ["./"],
            "exclude_patterns": [],
            "hash_algorithm": "sha256",
            "dual_hash": False,
            "store_path": "./audit_store",
            "ontology_file": "audit.ttl",
            "scan_interval_seconds": 300,
            "max_file_size_bytes": 524288000,
            "file_categories": {},
            "log_level": "INFO",
            "enable_watchdog": False,
            "compact_after_events": 10000,
        }), encoding="utf-8")
        (tmp_path / "audit_store").mkdir()
        subfile = tmp_path / "main.py"
        subfile.write_text("pass", encoding="utf-8")
        agent = get_agent_for_path(subfile, auto_init=False)
        assert agent is not None
