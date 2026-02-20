"""
ATUM Audit Agent - Core agent with real-time monitoring and periodic scanning.
Production-grade: thread-safe, graceful shutdown, structured logging.
"""

import json
import logging
import mimetypes
import signal
import sys
import threading
import time
from fnmatch import fnmatch
from pathlib import Path

from watchdog.events import (
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from .compliance import ComplianceManager
from .hasher import compute_dual_hash, compute_hash
from .store import ATUM, AuditStore

logger = logging.getLogger("atum_audit.agent")

__all__ = ["AuditAgent", "AuditEventHandler"]


class AuditEventHandler(FileSystemEventHandler):
    """Watchdog handler: translates FS events into audit records."""

    def __init__(self, agent: "AuditAgent"):
        super().__init__()
        self._agent = agent

    def on_created(self, event):
        if not event.is_directory:
            self._agent.process_file_event(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._agent.process_file_event(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self._agent.process_file_event(event.src_path, "deleted")

    def on_moved(self, event):
        if not event.is_directory:
            self._agent.process_file_event(event.src_path, "moved", dest=event.dest_path)


class AuditAgent:
    """
    Main audit agent. Combines:
    - Real-time filesystem monitoring (watchdog)
    - Periodic full integrity scans
    - Cryptographic hash computation
    - OWL/RDF audit trail persistence
    """

    def __init__(self, config_path: str = "atum-audit.config.json"):
        # Load config — resolve to anchor relative paths
        cfg_path = Path(config_path).resolve()
        self._config_dir = cfg_path.parent
        if cfg_path.exists():
            with open(cfg_path, encoding="utf-8") as f:
                self._config = json.load(f)
        else:
            self._config = self._defaults()

        # Setup logging — configure the package logger, not the root logger
        log_level = getattr(logging, self._config.get("log_level", "INFO"))
        pkg_logger = logging.getLogger("atum_audit")
        pkg_logger.setLevel(log_level)
        if not pkg_logger.handlers or all(
            isinstance(h, logging.NullHandler) for h in pkg_logger.handlers
        ):
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            ))
            pkg_logger.addHandler(handler)

        # Resolve paths relative to config file directory
        store_raw = Path(self._config["store_path"])
        if store_raw.is_absolute():
            self._store_path = store_raw.resolve()
        else:
            self._store_path = (self._config_dir / store_raw).resolve()
        self._store_path.mkdir(parents=True, exist_ok=True)

        # Find ontology
        ontology_path = Path(__file__).parent / "ontology.ttl"
        if not ontology_path.exists():
            ontology_path = self._store_path / "ontology.ttl"

        # Initialize store
        self._store = AuditStore(
            store_dir=self._store_path,
            ontology_path=ontology_path,
            data_file=self._config.get("ontology_file", "audit.ttl"),
        )

        # Register this agent
        self._agent_uri = self._store.ensure_agent("atum-audit-daemon", "daemon")

        # EU AI Act compliance (optional)
        self._compliance = ComplianceManager(self._store)
        self._ai_system_uri = None
        ai_cfg = self._config.get("ai_system")
        if ai_cfg and isinstance(ai_cfg, dict) and ai_cfg.get("name"):
            self._ai_system_uri = self._compliance.register_ai_system(
                name=ai_cfg["name"],
                risk_level=ai_cfg.get("risk_level", "minimal"),
                compliance_status=ai_cfg.get("compliance_status", "pending"),
                lifecycle_phase=ai_cfg.get("lifecycle_phase", "development"),
                description=ai_cfg.get("description", ""),
                intended_purpose=ai_cfg.get("intended_purpose", ""),
                provider_name=ai_cfg.get("provider_name", ""),
                retention_months=ai_cfg.get("retention_months", 6),
            )
            logger.info("AI system registered: %s", ai_cfg["name"])

        # Pre-resolve watch paths relative to config dir (immutable after init)
        self._resolved_watch_paths: tuple[Path, ...] = tuple(
            (self._config_dir / Path(wp)).resolve() if not Path(wp).is_absolute()
            else Path(wp).resolve()
            for wp in self._config["watch_paths"]
        )

        # State
        self._observer: Observer | None = None
        self._shutdown = threading.Event()
        self._scan_lock = threading.Lock()
        self._debounce: dict[str, float] = {}
        self._debounce_lock = threading.Lock()
        self._debounce_seconds = 1.0
        self._debounce_cleanup_threshold = 1000

    @staticmethod
    def _defaults() -> dict:
        return {
            "watch_paths": ["./"],
            "exclude_patterns": [
                "**/.git/**", "**/__pycache__/**", "**/node_modules/**",
                "**/.venv/**", "**/.DS_Store", "**/audit_store/**",
            ],
            "hash_algorithm": "sha256",
            "dual_hash": False,
            "store_path": "./audit_store",
            "ontology_file": "audit.ttl",
            "scan_interval_seconds": 300,
            "max_file_size_bytes": 524288000,
            "file_categories": {},
            "project_detection": "directory",
            "log_level": "INFO",
            "enable_watchdog": True,
            "compact_after_events": 10000,
        }

    @property
    def project_root(self) -> Path:
        """Directory containing this agent's config file."""
        return self._config_dir

    def _is_excluded(self, filepath: str) -> bool:
        """Check if a path matches any exclusion pattern."""
        p = Path(filepath)
        for pattern in self._config.get("exclude_patterns", []):
            if fnmatch(filepath, pattern):
                return True
            for wp_resolved in self._resolved_watch_paths:
                if p.is_relative_to(wp_resolved) and fnmatch(
                    str(p.relative_to(wp_resolved)), pattern
                ):
                    return True
        return False

    def _classify_file(self, filepath: Path) -> str:
        """Determine file category from extension."""
        ext = filepath.suffix.lower()
        categories = self._config.get("file_categories", {})
        for cat_name, extensions in categories.items():
            if ext in extensions:
                return cat_name
        return "other"

    def _detect_project(self, filepath: Path) -> str | None:
        """Detect which project a file belongs to."""
        mode = self._config.get("project_detection", "directory")
        for wp_resolved in self._resolved_watch_paths:
            try:
                rel = filepath.resolve().relative_to(wp_resolved)
                parts = rel.parts
                if not parts:
                    return None
                if mode == "directory":
                    return parts[0]
                elif mode == "git":
                    current = filepath.resolve()
                    while current != wp_resolved and current != current.parent:
                        if (current / ".git").exists():
                            return current.name
                        current = current.parent
                elif mode == "marker_file":
                    current = filepath.resolve().parent
                    while current != wp_resolved and current != current.parent:
                        if (current / ".atum-project").exists():
                            return current.name
                        current = current.parent
            except ValueError:
                continue
        return None

    def _is_debounced(self, filepath: str) -> bool:
        """Debounce rapid duplicate events on same file. Thread-safe."""
        now = time.time()
        with self._debounce_lock:
            last = self._debounce.get(filepath, 0)
            if now - last < self._debounce_seconds:
                return True

            self._debounce[filepath] = now

            # Periodic cleanup: prevent unbounded growth
            if len(self._debounce) > self._debounce_cleanup_threshold:
                cutoff = now - self._debounce_seconds
                self._debounce = {
                    k: v for k, v in self._debounce.items() if v >= cutoff
                }

            return False

    # =========================================================================
    # Event processing
    # =========================================================================

    def process_file_event(self, filepath: str, event_type: str, dest: str = ""):
        """Process a single filesystem event."""
        if self._is_excluded(filepath):
            return
        if self._is_debounced(filepath):
            return

        fp = Path(filepath)
        logger.debug("Event: %s -> %s", event_type, filepath)

        try:
            if event_type == "deleted":
                self._handle_deletion(filepath)
            elif event_type == "moved":
                self._handle_move(filepath, dest)
            elif event_type in ("created", "modified"):
                self._handle_create_or_modify(fp, event_type)
        except Exception as e:
            logger.error("Error processing %s on %s: %s", event_type, filepath, e, exc_info=True)

    def _handle_create_or_modify(
        self,
        fp: Path,
        event_type: str,
        *,
        precomputed_hash: str | None = None,
        precomputed_secondary_hash: str | None = None,
    ):
        if not fp.exists() or not fp.is_file():
            return

        max_size = self._config.get("max_file_size_bytes")
        category = self._classify_file(fp)
        filepath_str = str(fp.resolve())

        # Use pre-computed hash if available (from full_scan), else compute
        if precomputed_hash is not None:
            primary_hash = precomputed_hash
            if self._config.get("dual_hash"):
                secondary_hash = precomputed_secondary_hash
                primary_algo = "sha256"
                secondary_algo = "blake2b" if secondary_hash else None
            else:
                secondary_hash = None
                primary_algo = self._config.get("hash_algorithm", "sha256")
                secondary_algo = None
        elif self._config.get("dual_hash"):
            result = compute_dual_hash(fp, max_size)
            if result is None:
                return
            primary_hash, secondary_hash = result
            primary_algo = "sha256"
            secondary_algo = "blake2b"
        else:
            algo = self._config.get("hash_algorithm", "sha256")
            primary_hash = compute_hash(fp, algo, max_size)
            if primary_hash is None:
                return
            primary_algo = algo
            secondary_hash = None
            secondary_algo = None

        # Check previous hash
        stored_hash = self._store.get_current_hash(filepath_str)

        # Determine integrity status
        if event_type == "created" or stored_hash is None:
            integrity = ATUM.New
            owl_event_type = (
                ATUM.FileCreated if event_type == "created" else ATUM.BaselineEstablished
            )
            alert = ATUM.Info
            desc = f"New file tracked: {fp.name}"
        elif stored_hash == primary_hash:
            # Hash unchanged — metadata-only change
            return
        else:
            # Hash changed
            integrity = ATUM.Verified
            owl_event_type = ATUM.FileModified
            alert = ATUM.Info
            desc = f"File modified: {fp.name} (hash changed)"

        # Get or create file entity
        file_uri = self._store.ensure_file(filepath_str, fp.suffix.lower(), category)

        # Detect and link project
        project_name = self._detect_project(fp)
        if project_name:
            proj_uri = self._store.ensure_project(project_name)
            self._store.link_file_to_project(file_uri, proj_uri)

        # Link to AI system if configured
        if self._ai_system_uri is not None:
            self._store.link_file_to_ai_system(file_uri, self._ai_system_uri)

        # Record version
        mime, _ = mimetypes.guess_type(str(fp))
        try:
            size = fp.stat().st_size
        except OSError:
            size = 0

        ver_uri = self._store.record_version(
            file_uri=file_uri,
            hash_value=primary_hash,
            algorithm=primary_algo,
            file_size=size,
            mime_type=mime or "",
            secondary_hash=secondary_hash,
            secondary_algorithm=secondary_algo,
        )

        # Record audit event
        self._store.record_event(
            file_uri=file_uri,
            event_type=owl_event_type,
            agent_uri=self._agent_uri,
            integrity_status=integrity,
            alert_level=alert,
            description=desc,
            version_uri=ver_uri,
        )

        logger.info(
            f"[{event_type.upper()}] {fp.name} | "
            f"{primary_algo}:{primary_hash[:16]}... | {category}"
        )

    def _handle_deletion(self, filepath: str):
        filepath_str = str(Path(filepath).resolve())
        file_uri = self._store.ensure_file(filepath_str)
        self._store.record_event(
            file_uri=file_uri,
            event_type=ATUM.FileDeleted,
            agent_uri=self._agent_uri,
            integrity_status=ATUM.Deleted,
            alert_level=ATUM.Warning,
            description=f"File deleted: {Path(filepath).name}",
        )
        logger.warning("[DELETED] %s", filepath)

    def _handle_move(self, src: str, dest: str):
        src_str = str(Path(src).resolve())
        file_uri = self._store.ensure_file(src_str)
        self._store.record_event(
            file_uri=file_uri,
            event_type=ATUM.FileMoved,
            agent_uri=self._agent_uri,
            integrity_status=ATUM.Verified,
            alert_level=ATUM.Info,
            description=f"Moved: {Path(src).name} -> {dest}",
        )
        if dest and Path(dest).exists():
            self.process_file_event(dest, "modified")

    # =========================================================================
    # Full scan
    # =========================================================================

    def full_scan(self):
        """
        Walk all watch paths, hash every file, compare with stored hashes.
        Detects: new files, modifications, integrity changes.
        """
        if not self._scan_lock.acquire(blocking=False):
            logger.debug("Scan already in progress, skipping")
            return

        try:
            logger.info("=== Full integrity scan started ===")
            scanned = 0
            new_files = 0
            modified = 0
            max_size = self._config.get("max_file_size_bytes")
            use_dual = self._config.get("dual_hash", False)

            known_paths: set[str] = set()

            for wp_resolved in self._resolved_watch_paths:
                if not wp_resolved.exists():
                    logger.warning("Watch path does not exist: %s", wp_resolved)
                    continue

                for fp in wp_resolved.rglob("*"):
                    if self._shutdown.is_set():
                        return
                    if not fp.is_file():
                        continue
                    if self._is_excluded(str(fp)):
                        continue

                    filepath_str = str(fp.resolve())
                    known_paths.add(filepath_str)
                    scanned += 1

                    # Compute hash once — respecting dual_hash config
                    secondary_hash = None
                    if use_dual:
                        result = compute_dual_hash(fp, max_size)
                        if result is None:
                            continue
                        current_hash, secondary_hash = result
                    else:
                        algo = self._config.get("hash_algorithm", "sha256")
                        current_hash = compute_hash(fp, algo, max_size)
                        if current_hash is None:
                            continue

                    stored_hash = self._store.get_current_hash(filepath_str)

                    if stored_hash is None:
                        self._handle_create_or_modify(
                            fp, "created",
                            precomputed_hash=current_hash,
                            precomputed_secondary_hash=secondary_hash,
                        )
                        new_files += 1
                    elif stored_hash != current_hash:
                        self._handle_create_or_modify(
                            fp, "modified",
                            precomputed_hash=current_hash,
                            precomputed_secondary_hash=secondary_hash,
                        )
                        modified += 1

            # Record scan event
            scan_agent = self._store.ensure_agent("atum-audit-scanner", "daemon")
            scan_file = self._store.ensure_file("__scan_meta__", "", "system")
            self._store.record_event(
                file_uri=scan_file,
                event_type=ATUM.PeriodicScan,
                agent_uri=scan_agent,
                integrity_status=ATUM.Verified,
                alert_level=ATUM.Info,
                description=f"Full scan: {scanned} files, {new_files} new, {modified} modified",
            )

            self._store.flush()
            logger.info(
                f"=== Scan complete: {scanned} files | "
                f"{new_files} new | {modified} modified ==="
            )

        finally:
            self._scan_lock.release()

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def start(self):
        """Start the agent: initial scan, then watchdog + periodic scans."""
        logger.info("ATUM Audit Agent starting...")
        logger.info(f"Watch paths: {self._config['watch_paths']}")
        logger.info(f"Hash algorithm: {self._config['hash_algorithm']}")
        logger.info(f"Dual hash: {self._config.get('dual_hash', False)}")
        logger.info(f"Store: {self._store_path}")

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Initial baseline scan
        self.full_scan()

        # Start watchdog
        if self._config.get("enable_watchdog", True):
            self._observer = Observer()
            handler = AuditEventHandler(self)
            for wp_resolved in self._resolved_watch_paths:
                if wp_resolved.exists():
                    self._observer.schedule(handler, str(wp_resolved), recursive=True)
                    logger.info(f"Watchdog monitoring: {wp_resolved}")
            self._observer.start()

        # Periodic scan loop
        interval = self._config.get("scan_interval_seconds", 300)
        logger.info(f"Periodic scan interval: {interval}s")

        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=interval)
            if not self._shutdown.is_set():
                self.full_scan()

    def stop(self):
        """Graceful shutdown."""
        logger.info("Shutting down...")
        self._shutdown.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        self._store.flush()
        logger.info(f"Final state: {self._store.get_stats()}")
        logger.info("ATUM Audit Agent stopped.")

    def _signal_handler(self, signum, frame):
        self.stop()
        sys.exit(0)

    # =========================================================================
    # CLI convenience
    # =========================================================================

    @property
    def compliance(self) -> ComplianceManager:
        """Access the EU AI Act compliance manager."""
        return self._compliance

    def flush(self) -> None:
        """Flush pending data to disk."""
        self._store.flush()

    def verify_file(self, filepath: str) -> dict:
        """One-shot integrity verification of a single file."""
        fp = Path(filepath).resolve()
        if not fp.exists():
            return {"status": "error", "message": "File not found"}

        algo = self._config.get("hash_algorithm", "sha256")
        current = compute_hash(fp, algo)
        stored = self._store.get_current_hash(str(fp))

        if stored is None:
            return {"status": "unknown", "message": "File not in audit trail"}
        if current == stored:
            return {"status": "verified", "hash": current, "algorithm": algo}
        return {
            "status": "VIOLATION",
            "expected": stored,
            "actual": current,
            "algorithm": algo,
        }

    def query(self, sparql: str) -> list:
        """Execute arbitrary SPARQL query."""
        return self._store.sparql(sparql)

    def stats(self) -> dict:
        return self._store.get_stats()

    def violations(self) -> list:
        return self._store.get_integrity_violations()

    def history(self, filepath: str) -> list:
        return self._store.get_file_history(str(Path(filepath).resolve()))
