"""Tests for ATUM Audit Agent."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from atum_audit.agent import AuditAgent
from atum_audit.hasher import compute_dual_hash, compute_hash, verify_hash
from atum_audit.store import ATUM, AuditStore


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_file(tmp_dir):
    f = tmp_dir / "test.txt"
    f.write_text("ATUM audit test content")
    return f


@pytest.fixture
def ontology_path():
    """Locate ontology.ttl relative to this test file."""
    p = Path(__file__).parent / "ontology.ttl"
    if p.exists():
        return p
    p2 = Path(__file__).parent.parent / "atum_audit" / "ontology.ttl"
    if p2.exists():
        return p2
    pytest.fail(f"ontology.ttl not found at {p} or {p2}")


def _make_agent_config(tmp_dir, **overrides):
    """Helper to create a standard test config."""
    config = {
        "watch_paths": [str(tmp_dir)],
        "store_path": str(tmp_dir / "audit_store"),
        "hash_algorithm": "sha256",
        "exclude_patterns": ["**/audit_store/**"],
        "log_level": "WARNING",
        "enable_watchdog": False,
        "scan_interval_seconds": 9999,
        "max_file_size_bytes": 524288000,
        "file_categories": {},
        "project_detection": "directory",
        **overrides,
    }
    cfg_path = tmp_dir / "test-config.json"
    cfg_path.write_text(json.dumps(config))
    return str(cfg_path)


# =========================================================================
# Hasher tests
# =========================================================================

class TestHasher:
    def test_sha256(self, sample_file):
        h = compute_hash(sample_file, "sha256")
        assert h is not None
        assert len(h) == 64

    def test_blake2b(self, sample_file):
        h = compute_hash(sample_file, "blake2b")
        assert h is not None
        assert len(h) == 64

    def test_dual_hash(self, sample_file):
        result = compute_dual_hash(sample_file)
        assert result is not None
        sha, blake = result
        assert len(sha) == 64
        assert len(blake) == 64
        assert sha != blake

    def test_deterministic(self, sample_file):
        h1 = compute_hash(sample_file, "sha256")
        h2 = compute_hash(sample_file, "sha256")
        assert h1 == h2

    def test_verify(self, sample_file):
        h = compute_hash(sample_file, "sha256")
        assert verify_hash(sample_file, h, "sha256")
        assert not verify_hash(sample_file, "deadbeef" * 8, "sha256")

    def test_nonexistent_file(self, tmp_dir):
        h = compute_hash(tmp_dir / "nope.txt", "sha256")
        assert h is None

    def test_max_size(self, sample_file):
        h = compute_hash(sample_file, "sha256", max_size=5)
        assert h is None

    def test_content_change_detected(self, sample_file):
        h1 = compute_hash(sample_file, "sha256")
        sample_file.write_text("Modified content")
        h2 = compute_hash(sample_file, "sha256")
        assert h1 != h2


# =========================================================================
# Store tests
# =========================================================================

class TestStore:
    def test_create_store(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path)
        assert store.triple_count > 0

    def test_file_entity(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path)
        uri = store.ensure_file("/test/file.txt", ".txt", "spec")
        uri2 = store.ensure_file("/test/file.txt")
        assert uri == uri2

    def test_record_version(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path)
        file_uri = store.ensure_file("/test/file.txt")
        ver = store.record_version(file_uri, "abcd1234" * 8, "sha256", 1024)
        assert ver is not None

    def test_hash_retrieval(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path)
        file_uri = store.ensure_file("/test/file.txt")
        store.record_version(file_uri, "abcd1234" * 8, "sha256", 1024)
        h = store.get_current_hash("/test/file.txt")
        assert h == "abcd1234" * 8

    def test_version_chain(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path)
        file_uri = store.ensure_file("/test/file.txt")
        store.record_version(file_uri, "aaaa" * 16, "sha256", 100)
        store.record_version(file_uri, "bbbb" * 16, "sha256", 200)
        h = store.get_current_hash("/test/file.txt")
        assert h == "bbbb" * 16

    def test_persistence(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path, flush_interval=1)
        file_uri = store.ensure_file("/test/persist.txt")
        store.record_version(file_uri, "cccc" * 16, "sha256", 50)
        store.flush()

        store2 = AuditStore(tmp_dir / "store", ontology_path)
        h = store2.get_current_hash("/test/persist.txt")
        assert h == "cccc" * 16

    def test_sparql(self, tmp_dir, ontology_path):
        store = AuditStore(tmp_dir / "store", ontology_path)
        store.ensure_file("/test/sparql.txt", ".txt", "spec")
        results = store.sparql("""
            PREFIX atum: <https://atum.dev/ontology/audit#>
            SELECT ?path WHERE { ?f atum:filePath ?path }
        """)
        paths = [r["path"] for r in results]
        assert "/test/sparql.txt" in paths

    # --- New optimization tests ---

    def test_index_consistency_after_operations(self, tmp_dir, ontology_path):
        """Verify indexes stay in sync through create/version/flush/reload."""
        store = AuditStore(tmp_dir / "store", ontology_path)

        for i in range(20):
            uri = store.ensure_file(f"/test/file_{i}.txt", ".txt", "spec")
            store.record_version(uri, f"{i:064x}", "sha256", i * 100)

        store._verify_indexes()

        for i in range(0, 20, 3):
            uri = store.ensure_file(f"/test/file_{i}.txt")
            store.record_version(uri, f"{i + 1000:064x}", "sha256", i * 200)

        store._verify_indexes()

        store.flush()
        store2 = AuditStore(tmp_dir / "store", ontology_path)
        store2._verify_indexes()

        for i in range(20):
            expected = f"{i + 1000:064x}" if i % 3 == 0 else f"{i:064x}"
            assert store2.get_current_hash(f"/test/file_{i}.txt") == expected

    def test_get_stats_includes_violations(self, tmp_dir, ontology_path):
        """Verify get_stats correctly counts only IntegrityViolation events."""
        store = AuditStore(tmp_dir / "store", ontology_path)

        file_uri = store.ensure_file("/test/file.txt")
        agent_uri = store.ensure_agent("test-agent")

        store.record_event(file_uri, ATUM.FileCreated, agent_uri, ATUM.New)
        store.record_event(
            file_uri, ATUM.IntegrityViolation, agent_uri,
            ATUM.Tampered, ATUM.Critical, "Tampered!",
        )

        stats = store.get_stats()
        assert stats["total_events"] == 2
        assert stats["integrity_violations"] == 1
        assert "data_triples" in stats

    def test_get_file_history_special_chars(self, tmp_dir, ontology_path):
        """Verify SPARQL injection is not possible via filepath."""
        store = AuditStore(tmp_dir / "store", ontology_path)

        evil_path = '/test/file" . ?x ?y ?z } #'
        file_uri = store.ensure_file(evil_path)
        agent_uri = store.ensure_agent("test-agent")
        store.record_event(file_uri, ATUM.FileCreated, agent_uri, ATUM.New)

        history = store.get_file_history(evil_path)
        assert isinstance(history, list)

    def test_flush_does_not_include_tbox(self, tmp_dir, ontology_path):
        """Verify flush only serializes ABox data, not ontology TBox."""
        store = AuditStore(tmp_dir / "store", ontology_path)

        store.ensure_file("/test/file.txt")
        store.flush()

        data_file = tmp_dir / "store" / "audit.ttl"
        content = data_file.read_text()
        assert "owl:Ontology" not in content
        assert "owl:Class" not in content
        assert "/test/file.txt" in content

    def test_ensure_idempotent_after_reload(self, tmp_dir, ontology_path):
        """Verify ensure_* returns same URIs after flush/reload."""
        store = AuditStore(tmp_dir / "store", ontology_path)

        uri1 = store.ensure_file("/test/file.txt", ".txt", "spec")
        proj1 = store.ensure_project("ProjectA")
        agent1 = store.ensure_agent("test-agent")
        store.flush()

        store2 = AuditStore(tmp_dir / "store", ontology_path)
        uri2 = store2.ensure_file("/test/file.txt")
        proj2 = store2.ensure_project("ProjectA")
        agent2 = store2.ensure_agent("test-agent")

        assert uri1 == uri2
        assert proj1 == proj2
        assert agent1 == agent2


# =========================================================================
# Agent tests
# =========================================================================

class TestAgent:
    def test_init(self, tmp_dir):
        cfg_path = _make_agent_config(tmp_dir, exclude_patterns=[])
        agent = AuditAgent(cfg_path)
        assert agent.stats()["tracked_files"] == 0

    def test_scan(self, tmp_dir):
        proj = tmp_dir / "projectA"
        proj.mkdir()
        (proj / "readme.txt").write_text("Project A docs")
        (proj / "main.py").write_text("print('hello')")

        cfg_path = _make_agent_config(
            tmp_dir,
            file_categories={"spec": [".txt"], "code": [".py"]},
        )

        agent = AuditAgent(cfg_path)
        agent.full_scan()

        stats = agent.stats()
        assert stats["tracked_files"] >= 2

    def test_verify(self, tmp_dir):
        f = tmp_dir / "verify_me.txt"
        f.write_text("integrity check")

        cfg_path = _make_agent_config(tmp_dir)
        agent = AuditAgent(cfg_path)
        agent.full_scan()

        result = agent.verify_file(str(f))
        assert result["status"] == "verified"

        f.write_text("tampered!")
        result = agent.verify_file(str(f))
        assert result["status"] == "VIOLATION"

    # --- New optimization tests ---

    def test_full_scan_no_double_hash(self, tmp_dir):
        """full_scan should hash each file exactly once, not twice."""
        proj = tmp_dir / "proj"
        proj.mkdir()
        (proj / "a.txt").write_text("content a")
        (proj / "b.txt").write_text("content b")

        cfg_path = _make_agent_config(tmp_dir)
        agent = AuditAgent(cfg_path)

        hashed_files: list[str] = []
        original_compute = compute_hash

        def counting_hash(filepath, *args, **kwargs):
            hashed_files.append(str(filepath))
            return original_compute(filepath, *args, **kwargs)

        with patch("atum_audit.agent.compute_hash", side_effect=counting_hash):
            agent.full_scan()

        # Each file should appear at most once (no double-hashing)
        assert len(hashed_files) == len(set(hashed_files))

    def test_full_scan_dual_hash(self, tmp_dir):
        """full_scan should use compute_dual_hash when dual_hash is True."""
        proj = tmp_dir / "proj"
        proj.mkdir()
        (proj / "a.txt").write_text("dual hash test")

        cfg_path = _make_agent_config(tmp_dir, dual_hash=True)
        agent = AuditAgent(cfg_path)

        dual_called = False
        original_dual = compute_dual_hash

        def tracking_dual(*args, **kwargs):
            nonlocal dual_called
            dual_called = True
            return original_dual(*args, **kwargs)

        with patch("atum_audit.agent.compute_dual_hash", side_effect=tracking_dual):
            agent.full_scan()

        assert dual_called

    def test_cached_watch_paths(self, tmp_dir):
        """Resolved watch paths should be cached as a tuple."""
        cfg_path = _make_agent_config(tmp_dir)
        agent = AuditAgent(cfg_path)

        assert hasattr(agent, "_resolved_watch_paths")
        assert isinstance(agent._resolved_watch_paths, tuple)
        assert len(agent._resolved_watch_paths) == 1

    def test_debounce_cleanup(self, tmp_dir):
        """Debounce dict should not grow unbounded."""
        cfg_path = _make_agent_config(tmp_dir)
        agent = AuditAgent(cfg_path)
        agent._debounce_cleanup_threshold = 5

        stale_time = time.time() - 10
        agent._debounce = {f"/old/file_{i}.txt": stale_time for i in range(10)}

        agent._is_debounced("/new/file.txt")
        assert len(agent._debounce) == 1

    def test_modification_detected_in_scan(self, tmp_dir):
        """Modified files during rescan should be detected."""
        f = tmp_dir / "track.txt"
        f.write_text("original")

        cfg_path = _make_agent_config(tmp_dir)
        agent = AuditAgent(cfg_path)
        agent.full_scan()

        stats_before = agent.stats()
        v1 = stats_before["total_versions"]

        f.write_text("changed!")
        agent.full_scan()

        stats_after = agent.stats()
        assert stats_after["total_versions"] > v1
