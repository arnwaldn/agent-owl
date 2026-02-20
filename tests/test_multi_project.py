"""Integration tests for multi-project ATUM support.

Tests that ATUM correctly handles multiple independent projects,
nested projects, and files outside any project.
"""

import json
from pathlib import Path

import pytest

from atum_audit.discovery import (
    CONFIG_FILENAME,
    AgentCache,
    auto_init_project,
    find_config,
    get_agent_for_path,
)


def _make_project(root: Path, marker: str = ".git") -> Path:
    """Create a minimal project directory with a marker and return it."""
    root.mkdir(parents=True, exist_ok=True)
    marker_path = root / marker
    if marker == ".git":
        marker_path.mkdir(exist_ok=True)
    else:
        marker_path.write_text("{}", encoding="utf-8")
    return root


class TestTwoIndependentProjects:
    """Two projects side-by-side must have separate stores."""

    def test_separate_stores(self, tmp_path: Path):
        proj_a = _make_project(tmp_path / "proj_a")
        proj_b = _make_project(tmp_path / "proj_b")

        auto_init_project(proj_a)
        auto_init_project(proj_b)

        assert (proj_a / CONFIG_FILENAME).is_file()
        assert (proj_b / CONFIG_FILENAME).is_file()
        assert (proj_a / "audit_store").is_dir()
        assert (proj_b / "audit_store").is_dir()

        # Configs are independent
        config_a = json.loads((proj_a / CONFIG_FILENAME).read_text(encoding="utf-8"))
        config_b = json.loads((proj_b / CONFIG_FILENAME).read_text(encoding="utf-8"))
        assert config_a["store_path"] == "./audit_store"
        assert config_b["store_path"] == "./audit_store"

    def test_agents_are_distinct(self, tmp_path: Path):
        proj_a = _make_project(tmp_path / "proj_a")
        proj_b = _make_project(tmp_path / "proj_b")

        file_a = proj_a / "main.py"
        file_b = proj_b / "main.py"
        file_a.write_text("print('a')", encoding="utf-8")
        file_b.write_text("print('b')", encoding="utf-8")

        agent_a = get_agent_for_path(file_a, auto_init=True)
        agent_b = get_agent_for_path(file_b, auto_init=True)

        assert agent_a is not None
        assert agent_b is not None
        assert agent_a is not agent_b
        assert agent_a.project_root != agent_b.project_root

    def test_correct_project_detected(self, tmp_path: Path):
        proj_a = _make_project(tmp_path / "proj_a")
        proj_b = _make_project(tmp_path / "proj_b")

        # Init both
        auto_init_project(proj_a)
        auto_init_project(proj_b)

        # File in proj_a should detect proj_a config
        file_a = proj_a / "src" / "app.py"
        file_a.parent.mkdir(parents=True, exist_ok=True)
        file_a.write_text("pass", encoding="utf-8")

        config = find_config(file_a)
        assert config is not None
        assert config.parent == proj_a


class TestNestedProjects:
    """Monorepo structure: outer project with inner sub-projects."""

    def test_inner_project_found_first(self, tmp_path: Path):
        outer = _make_project(tmp_path / "monorepo")
        inner = tmp_path / "monorepo" / "packages" / "core"
        inner.mkdir(parents=True)
        (inner / "package.json").write_text("{}", encoding="utf-8")

        auto_init_project(outer)
        auto_init_project(inner)

        file_in_inner = inner / "src" / "index.ts"
        file_in_inner.parent.mkdir(parents=True)
        file_in_inner.write_text("export {}", encoding="utf-8")

        config = find_config(file_in_inner)
        assert config is not None
        assert config.parent == inner  # Inner, not outer

    def test_outer_project_for_root_files(self, tmp_path: Path):
        outer = _make_project(tmp_path / "monorepo")
        inner = tmp_path / "monorepo" / "packages" / "core"
        inner.mkdir(parents=True)
        (inner / "package.json").write_text("{}", encoding="utf-8")

        auto_init_project(outer)
        auto_init_project(inner)

        file_in_outer = outer / "README.md"
        file_in_outer.write_text("# Monorepo", encoding="utf-8")

        config = find_config(file_in_outer)
        assert config is not None
        assert config.parent == outer  # Outer, not inner


class TestFileOutsideProject:
    """Files not inside any project should be skipped."""

    def test_no_project_no_init(self, tmp_path: Path):
        isolated = tmp_path / "random" / "dir"
        isolated.mkdir(parents=True)
        f = isolated / "notes.txt"
        f.write_text("hello", encoding="utf-8")

        agent = get_agent_for_path(f, auto_init=False)
        assert agent is None

    def test_auto_init_skips_without_marker(self, tmp_path: Path):
        isolated = tmp_path / "no_markers"
        isolated.mkdir(parents=True)
        f = isolated / "test.py"
        f.write_text("pass", encoding="utf-8")

        agent = get_agent_for_path(f, auto_init=True)
        assert agent is None
        assert not (isolated / CONFIG_FILENAME).exists()


class TestCacheWithMultiProject:
    """AgentCache correctly serves multiple projects."""

    def test_cache_serves_correct_agents(self, tmp_path: Path):
        proj_a = _make_project(tmp_path / "proj_a")
        proj_b = _make_project(tmp_path / "proj_b")

        cache = AgentCache(max_size=4)

        file_a = proj_a / "app.py"
        file_a.write_text("pass", encoding="utf-8")
        file_b = proj_b / "app.py"
        file_b.write_text("pass", encoding="utf-8")

        agent_a = get_agent_for_path(file_a, cache=cache, auto_init=True)
        agent_b = get_agent_for_path(file_b, cache=cache, auto_init=True)

        assert agent_a is not None
        assert agent_b is not None
        assert cache.size == 2

        # Same file → same agent from cache
        agent_a2 = get_agent_for_path(file_a, cache=cache, auto_init=True)
        assert agent_a2 is agent_a

    def test_cached_projects_lists_all(self, tmp_path: Path):
        proj_a = _make_project(tmp_path / "proj_a")
        proj_b = _make_project(tmp_path / "proj_b")

        cache = AgentCache(max_size=4)

        get_agent_for_path(proj_a / "f.py", cache=cache, auto_init=True)
        get_agent_for_path(proj_b / "f.py", cache=cache, auto_init=True)

        projects = cache.cached_projects()
        assert len(projects) == 2


class TestAutoInitBehavior:
    """Auto-init creates correct files for various project types."""

    @pytest.mark.parametrize(
        "marker",
        [".git", "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "Gemfile"],
    )
    def test_auto_init_for_various_markers(self, tmp_path: Path, marker: str):
        proj = _make_project(tmp_path / "proj", marker=marker)
        f = proj / "main.txt"
        f.write_text("content", encoding="utf-8")

        agent = get_agent_for_path(f, auto_init=True)
        assert agent is not None
        assert (proj / CONFIG_FILENAME).is_file()
        assert (proj / "audit_store").is_dir()
        assert (proj / ".gitignore").is_file()
        assert "audit_store/" in (proj / ".gitignore").read_text(encoding="utf-8")
