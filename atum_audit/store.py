"""
ATUM Audit Agent - OWL/RDF graph store.
Manages the Turtle-serialized ontology with all audit triples.
Thread-safe via ReentrantLock. O(1) lookups via in-memory indexes.
"""

import logging
import re
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, RDF, XSD

logger = logging.getLogger("atum_audit.store")

__all__ = ["AuditStore", "ATUM", "PROV", "DATA"]

ATUM = Namespace("https://atum.dev/ontology/audit#")
PROV = Namespace("http://www.w3.org/ns/prov#")
DATA = Namespace("https://atum.dev/data/")

_PREFIXES = {"atum": ATUM, "prov": PROV, "data": DATA, "dcterms": DCTERMS}
_URI_UNSAFE = re.compile(r"[^a-z0-9_-]")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SPARQL_WRITE_RE = re.compile(
    r"\b(INSERT|DELETE|DROP|CLEAR|CREATE|LOAD|COPY|MOVE|ADD)\b",
    re.IGNORECASE,
)


class AuditStore:
    """
    Persistent RDF graph store for audit events.
    Loads the base ontology (TBox) + accumulated data (ABox) into separate graphs.
    All mutations are serialized via a reentrant lock.
    O(1) entity lookups via in-memory indexes.
    """

    def __init__(
        self,
        store_dir: Path,
        ontology_path: Path,
        data_file: str = "audit.ttl",
        flush_interval: int = 50,
    ):
        self._store_dir = Path(store_dir)
        self._store_dir.mkdir(parents=True, exist_ok=True)
        self._data_path = self._store_dir / data_file
        self._ontology_path = ontology_path
        self._lock = threading.RLock()
        self._event_count = 0
        self._flush_interval = flush_interval
        self._dirty = False

        # TBox: ontology graph (read-only after init)
        self._tbox = Graph()
        for prefix, ns in _PREFIXES.items():
            self._tbox.bind(prefix, ns)

        if ontology_path.exists():
            self._tbox.parse(str(ontology_path), format="turtle")
            logger.info("Ontology loaded: %s (%d triples)", ontology_path, len(self._tbox))
        else:
            logger.warning("Ontology not found at %s", ontology_path)

        # ABox: mutable data graph (all mutations go here)
        self._abox = Graph()
        for prefix, ns in _PREFIXES.items():
            self._abox.bind(prefix, ns)

        if self._data_path.exists():
            self._abox.parse(str(self._data_path), format="turtle")
            logger.info("Data loaded: %s (%d triples)", self._data_path, len(self._abox))

        # Lazy merged graph for SPARQL queries needing TBox + ABox
        self._merged: Graph | None = None
        self._merged_stale = True

        # O(1) lookup indexes (populated from ABox)
        self._idx_filepath: dict[str, URIRef] = {}
        self._idx_file_hash: dict[str, str] = {}
        self._idx_project: dict[str, URIRef] = {}
        self._idx_agent: dict[str, URIRef] = {}
        self._idx_category: dict[str, URIRef] = {}
        self._idx_client: dict[str, URIRef] = {}
        self._idx_uri_to_filepath: dict[URIRef, str] = {}

        # EU AI Act indexes
        self._idx_ai_system: dict[str, URIRef] = {}
        self._idx_dataset: dict[str, URIRef] = {}
        self._idx_model_version: dict[tuple[str, str], URIRef] = {}
        self._idx_incident: dict[str, URIRef] = {}
        self._idx_risk: dict[str, URIRef] = {}

        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        """Scan the ABox and populate all lookup indexes. Called once at startup."""
        g = self._abox

        for s, o in g.subject_objects(ATUM.filePath):
            filepath_str = str(o)
            self._idx_filepath[filepath_str] = s
            self._idx_uri_to_filepath[s] = filepath_str

        for s, o in g.subject_objects(ATUM.categoryName):
            self._idx_category[str(o)] = s
        for s, o in g.subject_objects(ATUM.projectName):
            self._idx_project[str(o)] = s
        for s, o in g.subject_objects(ATUM.clientName):
            self._idx_client[str(o)] = s
        for s, o in g.subject_objects(ATUM.agentName):
            self._idx_agent[str(o)] = s

        # Hash index: filepath -> current hash value (expensive 4-level traversal, done once)
        for filepath_str, file_uri in self._idx_filepath.items():
            versions = list(g.objects(file_uri, ATUM.currentVersion))
            if len(versions) > 1:
                logger.warning(
                    "Multiple currentVersion triples for %s — taking first",
                    filepath_str,
                )
            if not versions:
                continue
            ver_uri = versions[0]
            for hash_uri in g.objects(ver_uri, ATUM.hasHash):
                for val in g.objects(hash_uri, ATUM.hashValue):
                    self._idx_file_hash[filepath_str] = str(val)
                    break  # Take first hash value only
                break  # Take first hash digest only

        # EU AI Act indexes
        for s, o in g.subject_objects(ATUM.systemName):
            self._idx_ai_system[str(o)] = s
        for s, o in g.subject_objects(ATUM.datasetName):
            self._idx_dataset[str(o)] = s
        for s, o in g.subject_objects(ATUM.incidentId):
            self._idx_incident[str(o)] = s
        for s, o in g.subject_objects(ATUM.riskId):
            self._idx_risk[str(o)] = s
        for mv_uri in g.subjects(RDF.type, ATUM.ModelVersion):
            tag = next((str(o) for o in g.objects(mv_uri, ATUM.modelVersionTag)), None)
            if tag is None:
                continue
            for sys_uri in g.subjects(ATUM.hasModelVersion, mv_uri):
                sys_name = next((str(o) for o in g.objects(sys_uri, ATUM.systemName)), None)
                if sys_name:
                    self._idx_model_version[(sys_name, tag)] = mv_uri
                break

        logger.debug(
            "Indexes rebuilt: %d files, %d hashes, %d projects, %d AI systems",
            len(self._idx_filepath), len(self._idx_file_hash),
            len(self._idx_project), len(self._idx_ai_system),
        )

    def _get_merged_graph(self) -> Graph:
        """Lazy merged graph for SPARQL queries needing TBox + ABox."""
        if self._merged is None or self._merged_stale:
            self._merged = self._tbox + self._abox
            self._merged_stale = False
        return self._merged

    @property
    def triple_count(self) -> int:
        return len(self._tbox) + len(self._abox)

    def _uri(self, prefix: str) -> URIRef:
        """Generate a unique URI for a new individual."""
        return DATA[f"{prefix}_{uuid.uuid4().hex[:12]}"]

    def _now(self) -> Literal:
        return Literal(datetime.now(UTC).isoformat(), datatype=XSD.dateTime)

    def _mark_dirty(self) -> None:
        """Mark data as needing flush and invalidate merged graph cache.

        MUST be called with self._lock held.
        """
        self._dirty = True
        self._merged_stale = True

    def flush(self) -> None:
        """Serialize ABox (data only) to disk. Ontology is never flushed."""
        with self._lock:
            if not self._dirty:
                return
            tmp = self._data_path.with_suffix(".tmp")
            self._abox.serialize(str(tmp), format="turtle")
            tmp.replace(self._data_path)
            self._dirty = False
            logger.debug("Flushed %d data triples to %s", len(self._abox), self._data_path)

    def _maybe_flush(self) -> None:
        """Auto-flush after N events. MUST be called with self._lock held."""
        self._event_count += 1
        if self._event_count % self._flush_interval == 0:
            self.flush()

    # =========================================================================
    # Entity creation (O(1) via indexes)
    # =========================================================================

    def ensure_file(self, filepath: str, extension: str = "", category: str = "") -> URIRef:
        """Get or create a File individual. O(1) lookup via index."""
        with self._lock:
            existing = self._idx_filepath.get(filepath)
            if existing is not None:
                return existing

            uri = self._uri("file")
            self._abox.add((uri, RDF.type, ATUM.File))
            self._abox.add((uri, ATUM.filePath, Literal(filepath)))
            self._abox.add((uri, ATUM.fileName, Literal(Path(filepath).name)))
            if extension:
                self._abox.add((uri, ATUM.fileExtension, Literal(extension)))
            if category:
                cat_uri = self._ensure_category(category)
                self._abox.add((uri, ATUM.hasCategory, cat_uri))

            self._idx_filepath[filepath] = uri
            self._idx_uri_to_filepath[uri] = filepath
            self._mark_dirty()
            return uri

    def _ensure_category(self, name: str) -> URIRef:
        """Get or create a FileCategory. Thread-safe (acquires RLock)."""
        with self._lock:
            existing = self._idx_category.get(name)
            if existing is not None:
                return existing
            safe_name = _URI_UNSAFE.sub("_", name.lower())
            uri = DATA[f"cat_{safe_name}"]
            self._abox.add((uri, RDF.type, ATUM.FileCategory))
            self._abox.add((uri, ATUM.categoryName, Literal(name)))
            self._idx_category[name] = uri
            return uri

    def ensure_project(self, name: str) -> URIRef:
        with self._lock:
            existing = self._idx_project.get(name)
            if existing is not None:
                return existing
            uri = self._uri("proj")
            self._abox.add((uri, RDF.type, ATUM.Project))
            self._abox.add((uri, ATUM.projectName, Literal(name)))
            self._idx_project[name] = uri
            self._mark_dirty()
            return uri

    def ensure_client(self, name: str) -> URIRef:
        with self._lock:
            existing = self._idx_client.get(name)
            if existing is not None:
                return existing
            uri = self._uri("client")
            self._abox.add((uri, RDF.type, ATUM.Client))
            self._abox.add((uri, ATUM.clientName, Literal(name)))
            self._idx_client[name] = uri
            self._mark_dirty()
            return uri

    def ensure_agent(self, name: str, agent_type: str = "daemon") -> URIRef:
        with self._lock:
            existing = self._idx_agent.get(name)
            if existing is not None:
                return existing
            safe_name = _URI_UNSAFE.sub("_", name.lower())
            uri = DATA[f"agent_{safe_name}"]
            self._abox.add((uri, RDF.type, ATUM.Agent))
            self._abox.add((uri, ATUM.agentName, Literal(name)))
            self._abox.add((uri, ATUM.agentType, Literal(agent_type)))
            self._idx_agent[name] = uri
            self._mark_dirty()
            return uri

    def link_file_to_project(self, file_uri: URIRef, project_uri: URIRef) -> None:
        with self._lock:
            self._abox.add((file_uri, ATUM.belongsToProject, project_uri))
            self._mark_dirty()

    # =========================================================================
    # EU AI Act entity creation (Reg. 2024/1689)
    # =========================================================================

    def ensure_ai_system(
        self,
        name: str,
        risk_level: URIRef = ATUM.MinimalRisk,
        compliance_status: URIRef = ATUM.CompliancePending,
        lifecycle_phase: URIRef = ATUM.PhaseDevelopment,
        description: str = "",
        intended_purpose: str = "",
        provider_name: str = "",
        retention_months: int = 6,
    ) -> URIRef:
        """Get or create an AISystem individual (Art. 3). O(1) via index."""
        with self._lock:
            existing = self._idx_ai_system.get(name)
            if existing is not None:
                return existing
            uri = self._uri("aisys")
            self._abox.add((uri, RDF.type, ATUM.AISystem))
            self._abox.add((uri, ATUM.systemName, Literal(name)))
            self._abox.add((uri, ATUM.hasRiskLevel, risk_level))
            self._abox.add((uri, ATUM.hasComplianceStatus, compliance_status))
            self._abox.add((uri, ATUM.hasLifecyclePhase, lifecycle_phase))
            if description:
                self._abox.add((uri, ATUM.systemDescription, Literal(description)))
            if intended_purpose:
                self._abox.add((uri, ATUM.intendedPurpose, Literal(intended_purpose)))
            if provider_name:
                self._abox.add((uri, ATUM.providerName, Literal(provider_name)))
            self._abox.add((
                uri, ATUM.retentionMinMonths,
                Literal(retention_months, datatype=XSD.positiveInteger),
            ))
            self._idx_ai_system[name] = uri
            self._mark_dirty()
            return uri

    def ensure_dataset(
        self, name: str, description: str = "", size: int = 0,
    ) -> URIRef:
        """Get or create a Dataset individual (Art. 10). O(1) via index."""
        with self._lock:
            existing = self._idx_dataset.get(name)
            if existing is not None:
                return existing
            uri = self._uri("dataset")
            self._abox.add((uri, RDF.type, ATUM.Dataset))
            self._abox.add((uri, ATUM.datasetName, Literal(name)))
            if description:
                self._abox.add((uri, ATUM.datasetDescription, Literal(description)))
            if size > 0:
                self._abox.add((uri, ATUM.datasetSize, Literal(size, datatype=XSD.long)))
            self._idx_dataset[name] = uri
            self._mark_dirty()
            return uri

    def link_file_to_ai_system(self, file_uri: URIRef, system_uri: URIRef) -> None:
        """Link a tracked file to an AI system."""
        with self._lock:
            self._abox.add((file_uri, ATUM.belongsToAISystem, system_uri))
            self._mark_dirty()

    def update_compliance_status(self, system_uri: URIRef, status: URIRef) -> None:
        """Update compliance status of an AI system (Art. 17)."""
        with self._lock:
            self._abox.remove((system_uri, ATUM.hasComplianceStatus, None))
            self._abox.add((system_uri, ATUM.hasComplianceStatus, status))
            self._mark_dirty()

    def update_lifecycle_phase(self, system_uri: URIRef, phase: URIRef) -> None:
        """Update lifecycle phase of an AI system."""
        with self._lock:
            self._abox.remove((system_uri, ATUM.hasLifecyclePhase, None))
            self._abox.add((system_uri, ATUM.hasLifecyclePhase, phase))
            self._mark_dirty()

    def record_model_version(
        self,
        system_uri: URIRef,
        version_tag: str,
        performance_metrics: str = "",
        training_data_uri: URIRef | None = None,
        validation_data_uri: URIRef | None = None,
        test_data_uri: URIRef | None = None,
    ) -> URIRef:
        """Record a new model version with optional data lineage (Art. 11)."""
        with self._lock:
            sys_name = next(
                (str(o) for o in self._abox.objects(system_uri, ATUM.systemName)), None,
            )
            key = (sys_name, version_tag) if sys_name else None
            if key and key in self._idx_model_version:
                return self._idx_model_version[key]

            uri = self._uri("model")
            self._abox.add((uri, RDF.type, ATUM.ModelVersion))
            self._abox.add((uri, ATUM.modelVersionTag, Literal(version_tag)))
            self._abox.add((uri, ATUM.modelTrainedAt, self._now()))
            if performance_metrics:
                self._abox.add((uri, ATUM.performanceMetrics, Literal(performance_metrics)))
            if training_data_uri:
                self._abox.add((uri, ATUM.hasTrainingData, training_data_uri))
            if validation_data_uri:
                self._abox.add((uri, ATUM.hasValidationData, validation_data_uri))
            if test_data_uri:
                self._abox.add((uri, ATUM.hasTestData, test_data_uri))

            self._abox.remove((system_uri, ATUM.currentModelVersion, None))
            self._abox.add((system_uri, ATUM.currentModelVersion, uri))
            self._abox.add((system_uri, ATUM.hasModelVersion, uri))

            if key:
                self._idx_model_version[key] = uri
            self._mark_dirty()
            self._maybe_flush()
            return uri

    def record_incident(
        self,
        system_uri: URIRef,
        incident_id: str,
        description: str,
        severity: URIRef = ATUM.SeverityMedium,
        reporting_deadline_iso: str | None = None,
    ) -> URIRef:
        """Record an incident involving an AI system (Art. 62)."""
        with self._lock:
            existing = self._idx_incident.get(incident_id)
            if existing is not None:
                return existing
            uri = self._uri("incident")
            self._abox.add((uri, RDF.type, ATUM.Incident))
            self._abox.add((uri, ATUM.incidentId, Literal(incident_id)))
            self._abox.add((uri, ATUM.incidentDescription, Literal(description)))
            self._abox.add((uri, ATUM.incidentTimestamp, self._now()))
            self._abox.add((uri, ATUM.involvesSystem, system_uri))
            self._abox.add((uri, ATUM.hasIncidentSeverity, severity))
            if reporting_deadline_iso:
                self._abox.add((
                    uri, ATUM.reportingDeadline,
                    Literal(reporting_deadline_iso, datatype=XSD.dateTime),
                ))
            self._idx_incident[incident_id] = uri
            self._mark_dirty()
            self._maybe_flush()
            return uri

    def record_risk_assessment(self, system_uri: URIRef) -> URIRef:
        """Record a risk assessment for an AI system (Art. 9)."""
        with self._lock:
            uri = self._uri("riskassess")
            self._abox.add((uri, RDF.type, ATUM.RiskAssessment))
            self._abox.add((uri, ATUM.timestamp, self._now()))
            self._abox.add((system_uri, ATUM.hasRiskAssessment, uri))
            self._mark_dirty()
            return uri

    def record_risk(
        self,
        assessment_uri: URIRef,
        risk_id: str,
        description: str,
        residual_level: str = "",
    ) -> URIRef:
        """Record an identified risk within an assessment (Art. 9, para. 2)."""
        with self._lock:
            existing = self._idx_risk.get(risk_id)
            if existing is not None:
                return existing
            uri = self._uri("risk")
            self._abox.add((uri, RDF.type, ATUM.Risk))
            self._abox.add((uri, ATUM.riskId, Literal(risk_id)))
            self._abox.add((uri, ATUM.riskDescription, Literal(description)))
            if residual_level:
                self._abox.add((uri, ATUM.residualRiskLevel, Literal(residual_level)))
            self._abox.add((assessment_uri, ATUM.identifiesRisk, uri))
            self._idx_risk[risk_id] = uri
            self._mark_dirty()
            return uri

    def record_mitigation(
        self, risk_uri: URIRef, description: str, status: str = "planned",
    ) -> URIRef:
        """Record a mitigation measure for a risk (Art. 9, para. 4)."""
        with self._lock:
            uri = self._uri("mitigation")
            self._abox.add((uri, RDF.type, ATUM.MitigationMeasure))
            self._abox.add((uri, ATUM.mitigationDescription, Literal(description)))
            self._abox.add((uri, ATUM.mitigationStatus, Literal(status)))
            self._abox.add((risk_uri, ATUM.hasMitigation, uri))
            self._abox.add((uri, ATUM.mitigatesRisk, risk_uri))
            self._mark_dirty()
            return uri

    def record_conformity_assessment(
        self,
        system_uri: URIRef,
        assessor_name: str,
        result: str,
    ) -> URIRef:
        """Record a conformity assessment (Art. 43)."""
        with self._lock:
            uri = self._uri("conform")
            self._abox.add((uri, RDF.type, ATUM.ConformityAssessment))
            self._abox.add((uri, ATUM.assessorName, Literal(assessor_name)))
            self._abox.add((uri, ATUM.assessmentDate, self._now()))
            self._abox.add((uri, ATUM.assessmentResult, Literal(result)))
            self._abox.add((system_uri, ATUM.hasConformityAssessment, uri))
            self._mark_dirty()
            return uri

    def record_human_oversight(
        self,
        system_uri: URIRef,
        description: str,
        actor: str,
    ) -> URIRef:
        """Record a human oversight action (Art. 14)."""
        with self._lock:
            uri = self._uri("oversight")
            self._abox.add((uri, RDF.type, ATUM.HumanOversightAction))
            self._abox.add((uri, ATUM.oversightDescription, Literal(description)))
            self._abox.add((uri, ATUM.oversightTimestamp, self._now()))
            self._abox.add((uri, ATUM.oversightActor, Literal(actor)))
            self._abox.add((system_uri, ATUM.hasOversightAction, uri))
            self._mark_dirty()
            return uri

    # =========================================================================
    # Version + Hash recording
    # =========================================================================

    def record_version(
        self,
        file_uri: URIRef,
        hash_value: str,
        algorithm: str,
        file_size: int,
        mime_type: str = "",
        secondary_hash: str | None = None,
        secondary_algorithm: str | None = None,
    ) -> URIRef:
        """
        Create a new FileVersion with its HashDigest.
        Links to previous version if one exists.
        Returns the version URI.
        """
        with self._lock:
            if not _HEX_RE.fullmatch(hash_value):
                raise ValueError(f"Invalid hex hash value: {hash_value!r}")
            if secondary_hash and not _HEX_RE.fullmatch(secondary_hash):
                raise ValueError(f"Invalid hex secondary hash: {secondary_hash!r}")

            # Get current version (will become previous)
            prev_version = None
            for o in self._abox.objects(file_uri, ATUM.currentVersion):
                prev_version = o
                break

            # Determine version number
            version_num = 1
            if prev_version:
                for o in self._abox.objects(prev_version, ATUM.versionNumber):
                    version_num = int(o) + 1
                    break

            # Create version
            ver_uri = self._uri("ver")
            self._abox.add((ver_uri, RDF.type, ATUM.FileVersion))
            self._abox.add((ver_uri, ATUM.versionTimestamp, self._now()))
            ver_num_lit = Literal(version_num, datatype=XSD.positiveInteger)
            self._abox.add((ver_uri, ATUM.versionNumber, ver_num_lit))
            self._abox.add((ver_uri, ATUM.fileSizeBytes, Literal(file_size, datatype=XSD.long)))
            if mime_type:
                self._abox.add((ver_uri, ATUM.mimeType, Literal(mime_type)))

            # Create primary hash
            hash_uri = self._uri("hash")
            self._abox.add((hash_uri, RDF.type, ATUM.HashDigest))
            self._abox.add((hash_uri, ATUM.hashValue, Literal(hash_value, datatype=XSD.hexBinary)))
            self._abox.add((hash_uri, ATUM.hashAlgorithm, Literal(algorithm)))
            self._abox.add((ver_uri, ATUM.hasHash, hash_uri))

            # Secondary hash if dual mode
            if secondary_hash and secondary_algorithm:
                hash2_uri = self._uri("hash")
                self._abox.add((hash2_uri, RDF.type, ATUM.HashDigest))
                sec_lit = Literal(secondary_hash, datatype=XSD.hexBinary)
                self._abox.add((hash2_uri, ATUM.hashValue, sec_lit))
                self._abox.add((hash2_uri, ATUM.hashAlgorithm, Literal(secondary_algorithm)))
                self._abox.add((ver_uri, ATUM["hasSecondaryHash"], hash2_uri))

            # Link version chain
            if prev_version:
                self._abox.add((ver_uri, ATUM.previousVersion, prev_version))

            # Update file's current version
            self._abox.remove((file_uri, ATUM.currentVersion, None))
            self._abox.add((file_uri, ATUM.currentVersion, ver_uri))
            self._abox.add((file_uri, ATUM.hasVersion, ver_uri))

            # Update hash index
            filepath_str = self._idx_uri_to_filepath.get(file_uri)
            if filepath_str is not None:
                self._idx_file_hash[filepath_str] = hash_value

            self._mark_dirty()
            self._maybe_flush()
            return ver_uri

    # =========================================================================
    # Audit event recording
    # =========================================================================

    def record_event(
        self,
        file_uri: URIRef,
        event_type: URIRef,
        agent_uri: URIRef,
        integrity_status: URIRef,
        alert_level: URIRef = ATUM.Info,
        description: str = "",
        version_uri: URIRef | None = None,
    ) -> URIRef:
        """Record an atomic audit event."""
        with self._lock:
            evt_uri = self._uri("evt")
            self._abox.add((evt_uri, RDF.type, ATUM.AuditEvent))
            self._abox.add((evt_uri, ATUM.timestamp, self._now()))
            self._abox.add((evt_uri, ATUM.hasEventType, event_type))
            self._abox.add((evt_uri, ATUM.concernsFile, file_uri))
            self._abox.add((evt_uri, ATUM.detectedBy, agent_uri))
            self._abox.add((evt_uri, ATUM.hasIntegrityStatus, integrity_status))
            self._abox.add((evt_uri, ATUM.hasAlertLevel, alert_level))
            if description:
                self._abox.add((evt_uri, ATUM.eventDescription, Literal(description)))
            if version_uri:
                self._abox.add((evt_uri, ATUM.concernsVersion, version_uri))
            self._mark_dirty()
            self._maybe_flush()
            return evt_uri

    # =========================================================================
    # Query helpers
    # =========================================================================

    def get_current_hash(self, filepath: str) -> str | None:
        """Get the latest hash value for a file path. O(1) via index."""
        with self._lock:
            return self._idx_file_hash.get(filepath)

    def get_tracked_files(self) -> dict[str, URIRef]:
        """Return a snapshot of tracked filepath -> URIRef mappings."""
        with self._lock:
            return dict(self._idx_filepath)

    def get_ai_system_names(self) -> list[str]:
        """Return all registered AI system names."""
        with self._lock:
            return list(self._idx_ai_system)

    def sparql(
        self,
        query_str: str,
        init_bindings: dict | None = None,
    ) -> list[dict[str, str]]:
        """
        Execute a read-only SPARQL query against the full graph (TBox + ABox).
        Write operations (INSERT, DELETE, etc.) are rejected.

        Args:
            query_str: SPARQL SELECT or CONSTRUCT query.
            init_bindings: Optional variable bindings (safe against injection).
        """
        if _SPARQL_WRITE_RE.search(query_str):
            raise ValueError("Only SELECT and CONSTRUCT queries are permitted.")
        with self._lock:
            merged = self._get_merged_graph()
            results = merged.query(query_str, initBindings=init_bindings or {})
            return [
                {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                for row in results
            ]

    def get_integrity_violations(self) -> list:
        """Return all events flagged as integrity violations."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        SELECT ?evt ?file ?path ?timestamp ?desc WHERE {
            ?evt a atum:AuditEvent ;
                 atum:hasEventType atum:IntegrityViolation ;
                 atum:concernsFile ?file ;
                 atum:timestamp ?timestamp .
            ?file atum:filePath ?path .
            OPTIONAL { ?evt atum:eventDescription ?desc }
        }
        ORDER BY DESC(?timestamp)
        """
        return self.sparql(q)

    def get_file_history(self, filepath: str) -> list:
        """Return full audit trail for a file. Uses parameterized query."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        SELECT ?evt ?eventType ?timestamp ?status ?desc WHERE {
            ?file atum:filePath ?fp .
            ?evt atum:concernsFile ?file ;
                 atum:hasEventType ?eventType ;
                 atum:timestamp ?timestamp ;
                 atum:hasIntegrityStatus ?status .
            OPTIONAL { ?evt atum:eventDescription ?desc }
        }
        ORDER BY DESC(?timestamp)
        """
        with self._lock:
            merged = self._get_merged_graph()
            results = merged.query(q, initBindings={"fp": Literal(filepath)})
            return [
                {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                for row in results
            ]

    # =========================================================================
    # EU AI Act queries (Reg. 2024/1689)
    # =========================================================================

    def get_compliance_status(self, system_name: str) -> dict | None:
        """Get compliance overview for an AI system (Art. 17)."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        SELECT ?system ?risk ?compliance ?phase ?desc ?purpose ?provider ?retention
        WHERE {
            ?system a atum:AISystem ;
                    atum:systemName ?name ;
                    atum:hasRiskLevel ?risk ;
                    atum:hasComplianceStatus ?compliance ;
                    atum:hasLifecyclePhase ?phase .
            OPTIONAL { ?system atum:systemDescription ?desc }
            OPTIONAL { ?system atum:intendedPurpose ?purpose }
            OPTIONAL { ?system atum:providerName ?provider }
            OPTIONAL { ?system atum:retentionMinMonths ?retention }
        }
        """
        with self._lock:
            merged = self._get_merged_graph()
            results = merged.query(q, initBindings={"name": Literal(system_name)})
            rows = [
                {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                for row in results
            ]
            return rows[0] if rows else None

    def get_system_files(self, system_name: str) -> list:
        """Get all files linked to an AI system."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        SELECT ?path ?ext ?hash WHERE {
            ?system a atum:AISystem ;
                    atum:systemName ?name .
            ?file atum:belongsToAISystem ?system ;
                  atum:filePath ?path .
            OPTIONAL { ?file atum:fileExtension ?ext }
            OPTIONAL {
                ?file atum:currentVersion ?ver .
                ?ver atum:hasHash ?hd .
                ?hd atum:hashValue ?hash .
            }
        }
        ORDER BY ?path
        """
        with self._lock:
            merged = self._get_merged_graph()
            results = merged.query(q, initBindings={"name": Literal(system_name)})
            return [
                {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                for row in results
            ]

    def get_incidents(self, system_name: str | None = None) -> list:
        """Get incidents, optionally filtered by AI system (Art. 62)."""
        if system_name:
            q = """
            PREFIX atum: <https://atum.dev/ontology/audit#>
            SELECT ?incId ?desc ?severity ?timestamp ?deadline WHERE {
                ?system a atum:AISystem ;
                        atum:systemName ?name .
                ?inc a atum:Incident ;
                     atum:involvesSystem ?system ;
                     atum:incidentId ?incId ;
                     atum:incidentDescription ?desc ;
                     atum:hasIncidentSeverity ?severity ;
                     atum:incidentTimestamp ?timestamp .
                OPTIONAL { ?inc atum:reportingDeadline ?deadline }
            }
            ORDER BY DESC(?timestamp)
            """
            with self._lock:
                merged = self._get_merged_graph()
                results = merged.query(q, initBindings={"name": Literal(system_name)})
                return [
                    {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                    for row in results
                ]
        else:
            q = """
            PREFIX atum: <https://atum.dev/ontology/audit#>
            SELECT ?incId ?sysName ?desc ?severity ?timestamp ?deadline WHERE {
                ?inc a atum:Incident ;
                     atum:involvesSystem ?system ;
                     atum:incidentId ?incId ;
                     atum:incidentDescription ?desc ;
                     atum:hasIncidentSeverity ?severity ;
                     atum:incidentTimestamp ?timestamp .
                ?system atum:systemName ?sysName .
                OPTIONAL { ?inc atum:reportingDeadline ?deadline }
            }
            ORDER BY DESC(?timestamp)
            """
            return self.sparql(q)

    def get_risk_assessment_report(self, system_name: str) -> list:
        """Get all risk assessments with identified risks for an AI system (Art. 9)."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        SELECT ?assessTime ?riskId ?riskDesc ?residual ?mitDesc ?mitStatus WHERE {
            ?system a atum:AISystem ;
                    atum:systemName ?name ;
                    atum:hasRiskAssessment ?assess .
            ?assess atum:timestamp ?assessTime .
            OPTIONAL {
                ?assess atum:identifiesRisk ?risk .
                ?risk atum:riskId ?riskId ;
                      atum:riskDescription ?riskDesc .
                OPTIONAL { ?risk atum:residualRiskLevel ?residual }
                OPTIONAL {
                    ?risk atum:hasMitigation ?mit .
                    ?mit atum:mitigationDescription ?mitDesc .
                    OPTIONAL { ?mit atum:mitigationStatus ?mitStatus }
                }
            }
        }
        ORDER BY ?assessTime ?riskId
        """
        with self._lock:
            merged = self._get_merged_graph()
            results = merged.query(q, initBindings={"name": Literal(system_name)})
            return [
                {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                for row in results
            ]

    def get_retention_violations(self) -> list:
        """Find AI systems whose log retention is below 6 months (Art. 12)."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
        SELECT ?name ?retention WHERE {
            ?system a atum:AISystem ;
                    atum:systemName ?name ;
                    atum:retentionMinMonths ?retention .
            FILTER (?retention < 6)
        }
        """
        return self.sparql(q)

    def get_model_lineage(self, system_name: str) -> list:
        """Get full model version history with data lineage (Art. 11)."""
        q = """
        PREFIX atum: <https://atum.dev/ontology/audit#>
        SELECT ?tag ?trainedAt ?metrics ?trainData ?valData ?testData WHERE {
            ?system a atum:AISystem ;
                    atum:systemName ?name ;
                    atum:hasModelVersion ?mv .
            ?mv atum:modelVersionTag ?tag ;
                atum:modelTrainedAt ?trainedAt .
            OPTIONAL { ?mv atum:performanceMetrics ?metrics }
            OPTIONAL {
                ?mv atum:hasTrainingData ?td .
                ?td atum:datasetName ?trainData .
            }
            OPTIONAL {
                ?mv atum:hasValidationData ?vd .
                ?vd atum:datasetName ?valData .
            }
            OPTIONAL {
                ?mv atum:hasTestData ?ted .
                ?ted atum:datasetName ?testData .
            }
        }
        ORDER BY ?trainedAt
        """
        with self._lock:
            merged = self._get_merged_graph()
            results = merged.query(q, initBindings={"name": Literal(system_name)})
            return [
                {str(var): str(row[var]) for var in results.vars if row[var] is not None}
                for row in results
            ]

    def export_system_graph(self, system_name: str) -> Graph:
        """Extract the sub-graph for a specific AI system and its related entities.

        Returns a new Graph containing the AISystem, its ModelVersions, Datasets,
        Incidents, RiskAssessments, and linked Files — suitable for isolated
        SHACL validation.
        """
        with self._lock:
            merged = self._get_merged_graph()
            result = Graph()
            for prefix, ns in _PREFIXES.items():
                result.bind(prefix, ns)

            system_uri = self._idx_ai_system.get(system_name)
            if system_uri is None:
                return result

            # Copy all triples where the system is subject or object
            for p, o in merged.predicate_objects(system_uri):
                result.add((system_uri, p, o))
                # Follow one level of linked entities
                if isinstance(o, URIRef):
                    for p2, o2 in merged.predicate_objects(o):
                        result.add((o, p2, o2))

            # Also copy files linked to this system
            for file_uri in merged.subjects(ATUM.belongsToAISystem, system_uri):
                for p, o in merged.predicate_objects(file_uri):
                    result.add((file_uri, p, o))

            # Copy incidents involving this system
            for inc_uri in merged.subjects(ATUM.involvesSystem, system_uri):
                for p, o in merged.predicate_objects(inc_uri):
                    result.add((inc_uri, p, o))

            # Copy class definitions (TBox) needed for SHACL validation
            for cls_uri in (
                ATUM.AISystem, ATUM.ModelVersion, ATUM.Dataset,
                ATUM.Incident, ATUM.RiskLevel, ATUM.ComplianceStatus,
                ATUM.LifecyclePhase, ATUM.IncidentSeverity,
            ):
                for p, o in self._tbox.predicate_objects(cls_uri):
                    result.add((cls_uri, p, o))

            # Copy enum individuals (needed for SHACL class constraints)
            enum_classes = (
                ATUM.RiskLevel, ATUM.ComplianceStatus,
                ATUM.LifecyclePhase, ATUM.IncidentSeverity,
            )
            for enum_cls in enum_classes:
                for ind in self._tbox.subjects(RDF.type, enum_cls):
                    for p, o in self._tbox.predicate_objects(ind):
                        result.add((ind, p, o))

            return result

    def get_stats(self) -> dict:
        """Return summary statistics including AI Act entities."""
        with self._lock:
            g = self._abox
            return {
                "total_triples": len(self._tbox) + len(g),
                "data_triples": len(g),
                "tracked_files": len(self._idx_filepath),
                "total_versions": len(list(g.subjects(RDF.type, ATUM.FileVersion))),
                "total_events": len(list(g.subjects(RDF.type, ATUM.AuditEvent))),
                "integrity_violations": sum(
                    1 for _ in g.triples((None, ATUM.hasEventType, ATUM.IntegrityViolation))
                ),
                # EU AI Act counters
                "ai_systems": len(self._idx_ai_system),
                "datasets": len(self._idx_dataset),
                "model_versions": len(self._idx_model_version),
                "incidents": len(self._idx_incident),
                "risks": len(self._idx_risk),
            }

    def _verify_indexes(self) -> bool:
        """Debug: verify all indexes match the graph. Raises AssertionError if not."""
        with self._lock:
            g = self._abox
            graph_filepaths = {str(o): s for s, o in g.subject_objects(ATUM.filePath)}
            assert graph_filepaths == self._idx_filepath, "filepath index mismatch"

            for filepath_str, expected_hash in self._idx_file_hash.items():
                file_uri = self._idx_filepath[filepath_str]
                actual = None
                for ver_uri in g.objects(file_uri, ATUM.currentVersion):
                    for hash_uri in g.objects(ver_uri, ATUM.hasHash):
                        for val in g.objects(hash_uri, ATUM.hashValue):
                            actual = str(val)
                assert actual == expected_hash, f"hash mismatch for {filepath_str}"

            # EU AI Act indexes
            graph_systems = {str(o): s for s, o in g.subject_objects(ATUM.systemName)}
            assert graph_systems == self._idx_ai_system, "ai_system index mismatch"

            graph_datasets = {str(o): s for s, o in g.subject_objects(ATUM.datasetName)}
            assert graph_datasets == self._idx_dataset, "dataset index mismatch"

            graph_incidents = {str(o): s for s, o in g.subject_objects(ATUM.incidentId)}
            assert graph_incidents == self._idx_incident, "incident index mismatch"

            graph_risks = {str(o): s for s, o in g.subject_objects(ATUM.riskId)}
            assert graph_risks == self._idx_risk, "risk index mismatch"

            return True
