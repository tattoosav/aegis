"""Context Graph Analyzer — correlates events across sensors to detect
multi-stage attack chains.

Maintains an in-memory rolling graph (default 30-minute window) where
nodes represent entities (processes, files, network connections, log
events) and edges represent relationships (spawned, modified, opened,
triggered).

The ``GraphAnalyzer`` runs pattern-matching queries against this graph
to detect 8 canonical attack chains, each mapped to MITRE ATT&CK
technique IDs.

Attack chains detected:
  1. drive_by_download     — browser -> file download -> execute
  2. credential_theft      — process -> credential file access -> exfil
  3. ransomware            — mass file encryption + ransom note
  4. persistence_install   — suspicious process -> Run key / Startup
  5. fileless_attack       — process -> powershell -enc -> network
  6. lateral_movement      — failed auth x N -> success -> new service
  7. data_exfiltration     — file reads -> external connection -> data
  8. dll_injection          — VirtualAllocEx -> WriteProcessMemory ->
                             CreateRemoteThread / Sysmon event 8
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from aegis.core.models import AegisEvent, SensorType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WINDOW_SECONDS = 1800.0  # 30 minutes
RANSOMWARE_FILE_THRESHOLD = 50
RANSOMWARE_TIME_WINDOW = 60.0  # seconds
EXFIL_FILE_READ_THRESHOLD = 20
EXFIL_DATA_VOLUME_THRESHOLD = 50_000_000  # 50 MB

# Browser process names (lowercase)
_BROWSER_NAMES: set[str] = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "vivaldi.exe",
}

# Browser credential database path fragments (lowercase)
_BROWSER_CREDENTIAL_PATHS: list[str] = [
    "login data", "logins.json", "cookies", "web data",
    "credential", "vault", "keychain",
]

# Persistence location indicators (lowercase)
_PERSISTENCE_INDICATORS: list[str] = [
    "\\run\\", "\\runonce\\", "\\startup\\",
    "\\start menu\\programs\\startup",
    "currentversion\\run",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """A node in the context graph representing an entity."""

    node_id: str
    node_type: str  # "process", "file", "network", "log"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class GraphEdge:
    """A directed edge between two graph nodes."""

    source_id: str
    target_id: str
    edge_type: str  # "spawned", "modified", "opened", "triggered"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class ChainMatch:
    """Result of an attack chain detection."""

    chain_name: str
    confidence: float
    mitre_ids: list[str] = field(default_factory=list)
    matched_nodes: list[str] = field(default_factory=list)
    description: str = ""
    severity: str = "HIGH"
    timestamp: float = 0.0


# ---------------------------------------------------------------------------
# Attack chain templates
# ---------------------------------------------------------------------------

ATTACK_CHAINS: dict[str, dict[str, Any]] = {
    "drive_by_download": {
        "stages": [
            "browser_navigation",
            "file_download",
            "file_execution",
        ],
        "mitre_ids": ["T1189", "T1204.002"],
        "confidence": 0.85,
        "severity": "CRITICAL",
    },
    "credential_theft": {
        "stages": [
            "process_access_credential_file",
            "credential_file_read",
            "network_exfil",
        ],
        "mitre_ids": ["T1555", "T1003"],
        "confidence": 0.9,
        "severity": "CRITICAL",
    },
    "ransomware": {
        "stages": [
            "mass_file_modification",
            "entropy_increase",
            "ransom_note_creation",
        ],
        "mitre_ids": ["T1486"],
        "confidence": 0.95,
        "severity": "CRITICAL",
    },
    "persistence_installation": {
        "stages": [
            "suspicious_process",
            "persistence_write",
        ],
        "mitre_ids": ["T1547.001", "T1053"],
        "confidence": 0.8,
        "severity": "HIGH",
    },
    "fileless_attack": {
        "stages": [
            "process_spawn_powershell_encoded",
            "powershell_network_connection",
            "no_file_on_disk",
        ],
        "mitre_ids": ["T1059.001", "T1027"],
        "confidence": 0.85,
        "severity": "CRITICAL",
    },
    "lateral_movement": {
        "stages": [
            "failed_auth_multiple",
            "successful_auth",
            "new_service_creation",
            "outbound_connection",
        ],
        "mitre_ids": ["T1021", "T1110"],
        "confidence": 0.8,
        "severity": "HIGH",
    },
    "data_exfiltration": {
        "stages": [
            "mass_file_read",
            "external_connection",
            "large_data_transfer",
        ],
        "mitre_ids": ["T1041", "T1567"],
        "confidence": 0.85,
        "severity": "CRITICAL",
    },
    "dll_injection": {
        "stages": [
            "virtual_alloc_ex",
            "write_process_memory",
            "create_remote_thread",
        ],
        "mitre_ids": ["T1055.001"],
        "confidence": 0.9,
        "severity": "CRITICAL",
    },
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _name_lower(data: dict[str, Any]) -> str:
    """Extract a lowercase process/file name from node data."""
    name = str(
        data.get("name", "")
        or data.get("process_name", "")
        or data.get("exe", "")
        or data.get("path", "")
        or "unknown"
    )
    return name.lower()


# ---------------------------------------------------------------------------
# ContextGraph — in-memory rolling graph
# ---------------------------------------------------------------------------

class ContextGraph:
    """In-memory directed graph with automatic time-based pruning.

    Nodes represent entities (processes, files, network connections,
    log entries).  Edges represent relationships.  Old entries beyond
    *window_seconds* are pruned automatically on each ``prune()`` call.
    """

    def __init__(self, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> None:
        self._window_seconds = window_seconds
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        # Adjacency list: source_id -> list of (edge, target_node)
        self._adjacency: dict[str, list[tuple[GraphEdge, GraphNode]]] = {}
        # Quick lookup: PID string -> node_id
        self._pid_to_node: dict[str, str] = {}

    # -- Properties ---------------------------------------------------------

    @property
    def window_seconds(self) -> float:
        return self._window_seconds

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # -- Node operations ----------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Add or update a node in the graph."""
        self._nodes[node.node_id] = node
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = []
        # Track PID mapping
        pid = node.data.get("pid")
        if pid is not None:
            self._pid_to_node[str(pid)] = node.node_id

    def get_node(self, node_id: str) -> GraphNode | None:
        """Retrieve a node by ID."""
        return self._nodes.get(node_id)

    def get_nodes_by_type(self, node_type: str) -> list[GraphNode]:
        """Return all nodes of a given type."""
        return [
            n for n in self._nodes.values()
            if n.node_type == node_type
        ]

    # -- Edge operations ----------------------------------------------------

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph."""
        self._edges.append(edge)
        if edge.source_id not in self._adjacency:
            self._adjacency[edge.source_id] = []
        target = self._nodes.get(edge.target_id)
        if target:
            self._adjacency[edge.source_id].append((edge, target))

    def get_neighbors(
        self,
        node_id: str,
        edge_type: str | None = None,
    ) -> list[GraphNode]:
        """Return neighbor nodes reachable from *node_id*.

        If *edge_type* is given, only follow edges of that type.
        """
        adj = self._adjacency.get(node_id, [])
        if edge_type is None:
            return [target for _, target in adj]
        return [
            target for edge, target in adj
            if edge.edge_type == edge_type
        ]

    # -- Pruning ------------------------------------------------------------

    def prune(self, now: float | None = None) -> int:
        """Remove nodes and edges older than the rolling window.

        Returns the number of nodes removed.
        """
        if now is None:
            now = time.time()
        cutoff = now - self._window_seconds

        # Find stale node IDs
        stale_ids: set[str] = set()
        for nid, node in list(self._nodes.items()):
            if node.timestamp < cutoff:
                stale_ids.add(nid)

        if not stale_ids:
            return 0

        # Remove stale nodes
        for nid in stale_ids:
            del self._nodes[nid]
            self._adjacency.pop(nid, None)

        # Remove stale edges
        self._edges = [
            e for e in self._edges
            if e.source_id not in stale_ids
            and e.target_id not in stale_ids
        ]

        # Rebuild adjacency for remaining nodes
        for nid in list(self._adjacency.keys()):
            if nid in stale_ids:
                continue
            self._adjacency[nid] = [
                (e, t) for e, t in self._adjacency.get(nid, [])
                if t.node_id not in stale_ids
            ]

        # Clean PID map
        self._pid_to_node = {
            pid: nid for pid, nid in self._pid_to_node.items()
            if nid not in stale_ids
        }

        return len(stale_ids)

    def clear(self) -> None:
        """Remove all nodes and edges."""
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()
        self._pid_to_node.clear()

    # -- Event ingestion ----------------------------------------------------

    def ingest_event(self, event: AegisEvent) -> GraphNode:
        """Convert an AegisEvent into graph nodes and edges.

        Creates a node for the event and links it to related
        entities already in the graph.

        Returns the primary node created.
        """
        now = event.timestamp
        data = dict(event.data) if event.data else {}
        data["event_type"] = event.event_type
        data["severity"] = event.severity.value

        # Determine node type from sensor
        sensor_to_type = {
            SensorType.PROCESS: "process",
            SensorType.FILE: "file",
            SensorType.NETWORK: "network",
            SensorType.EVENTLOG: "log",
        }
        node_type = sensor_to_type.get(event.sensor, "log")

        node_id = f"{node_type}_{event.event_type}_{id(event)}_{now}"
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            data=data,
            timestamp=now,
        )
        self.add_node(node)

        # Auto-link based on PID
        pid = data.get("pid") or data.get("process_id")
        ppid = data.get("ppid") or data.get("parent_pid")

        if pid and ppid:
            parent_nid = self._pid_to_node.get(str(ppid))
            if parent_nid:
                edge = GraphEdge(
                    source_id=parent_nid,
                    target_id=node_id,
                    edge_type="spawned",
                    timestamp=now,
                )
                self.add_edge(edge)

        # Link file events to their originating process
        if node_type == "file" and pid:
            proc_nid = self._pid_to_node.get(str(pid))
            if proc_nid:
                edge = GraphEdge(
                    source_id=proc_nid,
                    target_id=node_id,
                    edge_type="modified",
                    timestamp=now,
                )
                self.add_edge(edge)

        # Link network events to their originating process
        if node_type == "network" and pid:
            proc_nid = self._pid_to_node.get(str(pid))
            if proc_nid:
                edge = GraphEdge(
                    source_id=proc_nid,
                    target_id=node_id,
                    edge_type="opened",
                    timestamp=now,
                )
                self.add_edge(edge)

        # Link log events to their originating process
        if node_type == "log" and pid:
            proc_nid = self._pid_to_node.get(str(pid))
            if proc_nid:
                edge = GraphEdge(
                    source_id=proc_nid,
                    target_id=node_id,
                    edge_type="triggered",
                    timestamp=now,
                )
                self.add_edge(edge)

        return node


# ---------------------------------------------------------------------------
# GraphAnalyzer — attack chain pattern matching
# ---------------------------------------------------------------------------

class GraphAnalyzer:
    """Pattern-matching engine that detects attack chains in a ContextGraph.

    Runs all 8 attack chain checks against the current graph state
    and returns any matches found.
    """

    def __init__(
        self,
        graph: ContextGraph | None = None,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._graph = graph or ContextGraph(window_seconds)

    @property
    def graph(self) -> ContextGraph:
        """The underlying context graph."""
        return self._graph

    def ingest(self, event: AegisEvent) -> GraphNode:
        """Ingest an event into the graph."""
        return self._graph.ingest_event(event)

    def add_event(self, event: AegisEvent) -> GraphNode:
        """Alias for :meth:`ingest` (used by DetectionPipeline)."""
        return self.ingest(event)

    def analyze(self) -> list[ChainMatch]:
        """Run all attack chain detections and return matches.

        Prunes stale nodes first, then checks each chain template.
        """
        self._graph.prune()
        matches: list[ChainMatch] = []

        checkers = [
            self._check_drive_by_download,
            self._check_credential_theft,
            self._check_ransomware,
            self._check_persistence_installation,
            self._check_fileless_attack,
            self._check_lateral_movement,
            self._check_data_exfiltration,
            self._check_dll_injection,
        ]

        for checker in checkers:
            try:
                results = checker()
                matches.extend(results)
            except Exception as exc:
                logger.warning(
                    "Chain check %s failed: %s",
                    checker.__name__, exc,
                )

        if matches:
            logger.info(
                "GraphAnalyzer found %d attack chain match(es)",
                len(matches),
            )

        return matches

    # ------------------------------------------------------------------
    # 1. Drive-by download
    # ------------------------------------------------------------------

    def _check_drive_by_download(self) -> list[ChainMatch]:
        """Detect: browser -> file download -> execute.

        Stage 1: A browser process writes a file to disk.
        Stage 2: That file is subsequently executed as a new process.
        """
        chain_def = ATTACK_CHAINS["drive_by_download"]
        matches: list[ChainMatch] = []

        for proc_node in self._graph.get_nodes_by_type("process"):
            proc_name = _name_lower(proc_node.data)
            if proc_name not in _BROWSER_NAMES:
                continue

            # Files written by this browser
            file_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="modified"
            )
            executable_files = [
                f for f in file_neighbors
                if f.node_type == "file" and self._is_executable(f.data)
            ]

            for fnode in executable_files:
                # Check if a process was spawned from this file
                # (any process node whose path matches)
                file_path = str(
                    fnode.data.get("path", "")
                    or fnode.data.get("file_path", "")
                ).lower()
                if not file_path:
                    continue

                for exec_node in self._graph.get_nodes_by_type("process"):
                    exec_path = _name_lower(exec_node.data)
                    if (
                        file_path in exec_path
                        or exec_path in file_path
                    ) and exec_node.node_id != proc_node.node_id:
                        involved = [
                            proc_node.node_id,
                            fnode.node_id,
                            exec_node.node_id,
                        ]
                        matches.append(ChainMatch(
                            chain_name="drive_by_download",
                            confidence=chain_def["confidence"],
                            mitre_ids=list(chain_def["mitre_ids"]),
                            matched_nodes=involved,
                            description=(
                                f"Browser '{proc_name}' downloaded "
                                f"executable '{file_path}' which was "
                                f"then executed."
                            ),
                            severity=chain_def["severity"],
                            timestamp=time.time(),
                        ))

        return matches

    # ------------------------------------------------------------------
    # 2. Credential theft
    # ------------------------------------------------------------------

    def _check_credential_theft(self) -> list[ChainMatch]:
        """Detect: process -> credential file access -> network exfil.

        Stage 1: A non-browser process reads a browser credential file.
        Stage 2: That process opens a network connection (exfiltration).
        """
        chain_def = ATTACK_CHAINS["credential_theft"]
        matches: list[ChainMatch] = []

        for proc_node in self._graph.get_nodes_by_type("process"):
            proc_name = _name_lower(proc_node.data)
            if proc_name in _BROWSER_NAMES:
                continue  # Browsers reading their own creds is normal

            # Files accessed by this process
            file_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="modified"
            )
            cred_files = [
                f for f in file_neighbors
                if f.node_type == "file"
                and self._is_credential_path(f.data)
            ]
            if not cred_files:
                continue

            # Network connections from the same process
            net_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="opened"
            )
            if not net_neighbors:
                continue

            involved = (
                [proc_node.node_id]
                + [f.node_id for f in cred_files[:3]]
                + [n.node_id for n in net_neighbors[:2]]
            )
            matches.append(ChainMatch(
                chain_name="credential_theft",
                confidence=chain_def["confidence"],
                mitre_ids=list(chain_def["mitre_ids"]),
                matched_nodes=involved,
                description=(
                    f"Process '{proc_name}' accessed "
                    f"{len(cred_files)} credential file(s) and "
                    f"opened {len(net_neighbors)} network "
                    f"connection(s)."
                ),
                severity=chain_def["severity"],
                timestamp=time.time(),
            ))

        return matches

    # ------------------------------------------------------------------
    # 3. Ransomware
    # ------------------------------------------------------------------

    def _check_ransomware(self) -> list[ChainMatch]:
        """Detect: mass file modification + entropy increase.

        Stage 1: A single process modifies >= RANSOMWARE_FILE_THRESHOLD
                 files within RANSOMWARE_TIME_WINDOW seconds.
        Stage 2: Modified files show entropy increase (encryption).
        """
        chain_def = ATTACK_CHAINS["ransomware"]
        matches: list[ChainMatch] = []

        for proc_node in self._graph.get_nodes_by_type("process"):
            file_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="modified"
            )
            file_nodes = [
                f for f in file_neighbors if f.node_type == "file"
            ]

            if len(file_nodes) < RANSOMWARE_FILE_THRESHOLD:
                continue

            # Check time window
            if len(file_nodes) >= 2:
                timestamps = [f.timestamp for f in file_nodes]
                time_span = max(timestamps) - min(timestamps)
                if time_span > RANSOMWARE_TIME_WINDOW:
                    continue

            # Check entropy increase
            high_entropy_count = sum(
                1 for f in file_nodes
                if self._has_entropy_increase(f.data)
            )

            proc_name = _name_lower(proc_node.data)
            involved = (
                [proc_node.node_id]
                + [f.node_id for f in file_nodes[:10]]
            )
            desc_entropy = (
                f" with {high_entropy_count} showing entropy increase"
                if high_entropy_count > 0
                else ""
            )
            matches.append(ChainMatch(
                chain_name="ransomware",
                confidence=chain_def["confidence"],
                mitre_ids=list(chain_def["mitre_ids"]),
                matched_nodes=involved,
                description=(
                    f"Process '{proc_name}' modified "
                    f"{len(file_nodes)} files rapidly"
                    f"{desc_entropy}."
                ),
                severity=chain_def["severity"],
                timestamp=time.time(),
            ))

        return matches

    # ------------------------------------------------------------------
    # 4. Persistence installation
    # ------------------------------------------------------------------

    def _check_persistence_installation(self) -> list[ChainMatch]:
        """Detect: unsigned/temp process writes to persistence location.

        Stage 1: A process that is unsigned or running from a temporary
                 directory writes to a Run registry key, Startup folder,
                 or creates a scheduled task.
        """
        chain_def = ATTACK_CHAINS["persistence_installation"]
        matches: list[ChainMatch] = []

        for proc_node in self._graph.get_nodes_by_type("process"):
            if not self._is_suspicious_origin(proc_node.data):
                continue

            # Check file edges for Startup folder writes
            file_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="modified"
            )
            startup_writes = [
                f for f in file_neighbors
                if f.node_type == "file"
                and self._is_persistence_path(f.data)
            ]

            # Check log / registry events for Run key writes or
            # scheduled task creation
            log_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="triggered"
            )
            persistence_logs = [
                lg for lg in log_neighbors
                if self._is_persistence_event(lg.data)
            ]

            targets = startup_writes + persistence_logs
            if not targets:
                continue

            proc_name = _name_lower(proc_node.data)
            involved = (
                [proc_node.node_id]
                + [t.node_id for t in targets]
            )
            matches.append(ChainMatch(
                chain_name="persistence_installation",
                confidence=chain_def["confidence"],
                mitre_ids=list(chain_def["mitre_ids"]),
                matched_nodes=involved,
                description=(
                    f"Suspicious process '{proc_name}' wrote to a "
                    f"persistence location ({len(targets)} event(s))."
                ),
                severity=chain_def["severity"],
                timestamp=time.time(),
            ))

        return matches

    # ------------------------------------------------------------------
    # 5. Fileless attack
    # ------------------------------------------------------------------

    def _check_fileless_attack(self) -> list[ChainMatch]:
        """Detect: process -> powershell -enc -> network, no file on disk.

        Stage 1: A process spawns powershell with ``-enc`` or
                 ``-encodedcommand`` in the command line.
        Stage 2: PowerShell makes an outbound network connection.
        Stage 3: No file-write edge originates from PowerShell.
        """
        chain_def = ATTACK_CHAINS["fileless_attack"]
        matches: list[ChainMatch] = []

        for proc_node in self._graph.get_nodes_by_type("process"):
            # Stage 1: find child powershell with encoded command
            children = self._graph.get_neighbors(
                proc_node.node_id, edge_type="spawned"
            )
            ps_children = [
                c for c in children
                if _name_lower(c.data) in (
                    "powershell.exe", "pwsh.exe"
                )
                and self._has_encoded_flag(c.data)
            ]

            for ps in ps_children:
                # Stage 2: powershell opened a network connection?
                net_nodes = self._graph.get_neighbors(
                    ps.node_id, edge_type="opened"
                )
                if not net_nodes:
                    continue

                # Stage 3: powershell did NOT write a file to disk
                file_nodes = self._graph.get_neighbors(
                    ps.node_id, edge_type="modified"
                )
                if file_nodes:
                    # Files were written --- not pure fileless, lower
                    # confidence
                    confidence = chain_def["confidence"] * 0.7
                else:
                    confidence = chain_def["confidence"]

                involved = [
                    proc_node.node_id,
                    ps.node_id,
                    net_nodes[0].node_id,
                ]
                parent_name = _name_lower(proc_node.data)
                matches.append(ChainMatch(
                    chain_name="fileless_attack",
                    confidence=confidence,
                    mitre_ids=list(chain_def["mitre_ids"]),
                    matched_nodes=involved,
                    description=(
                        f"'{parent_name}' spawned PowerShell with an "
                        f"encoded command that made a network connection "
                        f"{'without' if not file_nodes else 'with'} "
                        f"writing to disk."
                    ),
                    severity=chain_def["severity"],
                    timestamp=time.time(),
                ))

        return matches

    # ------------------------------------------------------------------
    # 6. Lateral movement
    # ------------------------------------------------------------------

    def _check_lateral_movement(self) -> list[ChainMatch]:
        """Detect: failed auth x N -> success -> new service -> outbound.

        Stage 1: Multiple failed authentication log events.
        Stage 2: Successful authentication.
        Stage 3: New service or scheduled task creation.
        Stage 4: Outbound network connection from the new service.
        """
        chain_def = ATTACK_CHAINS["lateral_movement"]
        matches: list[ChainMatch] = []

        log_nodes = self._graph.get_nodes_by_type("log")

        failed_auths: list[GraphNode] = []
        successful_auths: list[GraphNode] = []
        service_events: list[GraphNode] = []

        for lnode in log_nodes:
            eid = str(lnode.data.get("event_id_win", ""))
            event_type = str(lnode.data.get("event_type", ""))

            if eid == "4625" or "failed_login" in event_type:
                failed_auths.append(lnode)
            elif eid == "4624" or "successful_login" in event_type:
                logon_type = str(lnode.data.get("logon_type", ""))
                if logon_type in ("3", "10") or not logon_type:
                    successful_auths.append(lnode)
            elif (
                eid in ("7045", "4697")
                or "service_install" in event_type
            ):
                service_events.append(lnode)

        if len(failed_auths) < 3 or not successful_auths:
            return matches

        failed_auths.sort(key=lambda n: n.timestamp)

        valid_successes = [
            s for s in successful_auths
            if s.timestamp >= failed_auths[0].timestamp
        ]
        if not valid_successes:
            return matches

        for success in valid_successes:
            new_services = [
                svc for svc in service_events
                if svc.timestamp >= success.timestamp
            ]
            if not new_services:
                continue

            for svc in new_services:
                involved = (
                    [f.node_id for f in failed_auths[:5]]
                    + [success.node_id, svc.node_id]
                )

                # Try to find network activity after service creation
                net_after = [
                    n for n in self._graph.get_nodes_by_type("network")
                    if n.timestamp >= svc.timestamp
                ]
                if net_after:
                    involved.append(net_after[0].node_id)

                matches.append(ChainMatch(
                    chain_name="lateral_movement",
                    confidence=chain_def["confidence"],
                    mitre_ids=list(chain_def["mitre_ids"]),
                    matched_nodes=involved,
                    description=(
                        f"{len(failed_auths)} failed auth attempts "
                        f"followed by successful logon, then new "
                        f"service/task created"
                        f"{' with outbound connection' if net_after else ''}."
                    ),
                    severity=chain_def["severity"],
                    timestamp=time.time(),
                ))
                break  # One match per success-service pair

        return matches

    # ------------------------------------------------------------------
    # 7. Data exfiltration
    # ------------------------------------------------------------------

    def _check_data_exfiltration(self) -> list[ChainMatch]:
        """Detect: process reads many files -> external conn -> large data.

        Stage 1: A process reads/modifies >= EXFIL_FILE_READ_THRESHOLD
                 files.
        Stage 2: Same process opens an external network connection.
        Stage 3: Outbound data volume exceeds threshold.
        """
        chain_def = ATTACK_CHAINS["data_exfiltration"]
        matches: list[ChainMatch] = []

        for proc_node in self._graph.get_nodes_by_type("process"):
            file_nodes = self._graph.get_neighbors(
                proc_node.node_id, edge_type="modified"
            )
            file_nodes = [
                f for f in file_nodes if f.node_type == "file"
            ]
            if len(file_nodes) < EXFIL_FILE_READ_THRESHOLD:
                continue

            net_nodes = self._graph.get_neighbors(
                proc_node.node_id, edge_type="opened"
            )
            external_nets = [
                n for n in net_nodes
                if n.node_type == "network"
                and self._is_external_connection(n.data)
            ]
            if not external_nets:
                continue

            total_bytes = sum(
                int(n.data.get("bytes_sent", 0) or 0)
                for n in external_nets
            )

            confidence = chain_def["confidence"]
            if total_bytes < EXFIL_DATA_VOLUME_THRESHOLD:
                confidence *= 0.6

            proc_name = _name_lower(proc_node.data)
            involved = (
                [proc_node.node_id]
                + [f.node_id for f in file_nodes[:5]]
                + [n.node_id for n in external_nets[:3]]
            )

            desc_volume = (
                f"{total_bytes / 1_000_000:.1f} MB sent"
                if total_bytes > 0
                else "data volume unknown"
            )
            matches.append(ChainMatch(
                chain_name="data_exfiltration",
                confidence=confidence,
                mitre_ids=list(chain_def["mitre_ids"]),
                matched_nodes=involved,
                description=(
                    f"Process '{proc_name}' accessed "
                    f"{len(file_nodes)} files and opened "
                    f"{len(external_nets)} external connection(s) "
                    f"({desc_volume})."
                ),
                severity=chain_def["severity"],
                timestamp=time.time(),
            ))

        return matches

    # ------------------------------------------------------------------
    # 8. DLL injection
    # ------------------------------------------------------------------

    def _check_dll_injection(self) -> list[ChainMatch]:
        """Detect: VirtualAllocEx -> WriteProcessMemory ->
        CreateRemoteThread, OR Sysmon event 8.

        Two detection paths:
        A) A process node has log neighbours showing the classic
           injection API call sequence.
        B) A Sysmon CreateRemoteThread event (event ID 8) exists.
        """
        chain_def = ATTACK_CHAINS["dll_injection"]
        matches: list[ChainMatch] = []
        seen_sources: set[str] = set()

        # --- Path A: API call sequence in log events ---
        for proc_node in self._graph.get_nodes_by_type("process"):
            log_neighbors = self._graph.get_neighbors(
                proc_node.node_id, edge_type="triggered"
            )

            has_virtual_alloc = False
            has_write_memory = False
            has_remote_thread = False
            involved_logs: list[str] = []

            for lg in log_neighbors:
                api = str(lg.data.get("api_call", "")).lower()
                etype = str(lg.data.get("event_type", "")).lower()
                combined = f"{api} {etype}"

                if "virtualallocex" in combined:
                    has_virtual_alloc = True
                    involved_logs.append(lg.node_id)
                if "writeprocessmemory" in combined:
                    has_write_memory = True
                    involved_logs.append(lg.node_id)
                if "createremotethread" in combined:
                    has_remote_thread = True
                    involved_logs.append(lg.node_id)

            if (
                has_virtual_alloc
                and has_write_memory
                and has_remote_thread
            ):
                proc_name = _name_lower(proc_node.data)
                involved = [proc_node.node_id] + involved_logs
                seen_sources.add(proc_node.node_id)
                matches.append(ChainMatch(
                    chain_name="dll_injection",
                    confidence=chain_def["confidence"],
                    mitre_ids=list(chain_def["mitre_ids"]),
                    matched_nodes=involved,
                    description=(
                        f"Process '{proc_name}' performed "
                        f"VirtualAllocEx + WriteProcessMemory + "
                        f"CreateRemoteThread sequence (classic DLL "
                        f"injection)."
                    ),
                    severity=chain_def["severity"],
                    timestamp=time.time(),
                ))

        # --- Path B: Sysmon event 8 (CreateRemoteThread) ---
        for lnode in self._graph.get_nodes_by_type("log"):
            eid = str(lnode.data.get("event_id_win", ""))
            etype = str(lnode.data.get("event_type", "")).lower()

            is_sysmon_8 = (
                eid == "8"
                or "createremotethread" in etype
                or "sysmon_8" in etype
            )
            if not is_sysmon_8:
                continue

            # Avoid duplicate if Path A already matched this process
            source_pid = (
                lnode.data.get("source_pid")
                or lnode.data.get("pid")
            )
            if source_pid:
                proc_nid = self._graph._pid_to_node.get(
                    str(source_pid)
                )
                if proc_nid and proc_nid in seen_sources:
                    continue

            involved = [lnode.node_id]
            if source_pid:
                proc_nid = self._graph._pid_to_node.get(
                    str(source_pid)
                )
                if proc_nid:
                    involved.insert(0, proc_nid)

            source_name = str(
                lnode.data.get("source_image", "")
                or lnode.data.get("source_name", "unknown")
            )
            target_name = str(
                lnode.data.get("target_image", "")
                or lnode.data.get("target_name", "unknown")
            )

            matches.append(ChainMatch(
                chain_name="dll_injection",
                confidence=chain_def["confidence"],
                mitre_ids=list(chain_def["mitre_ids"]),
                matched_nodes=involved,
                description=(
                    f"Sysmon CreateRemoteThread detected: "
                    f"'{source_name}' injected into "
                    f"'{target_name}'."
                ),
                severity=chain_def["severity"],
                timestamp=time.time(),
            ))

        return matches

    # ------------------------------------------------------------------
    # Private helper predicates
    # ------------------------------------------------------------------

    @staticmethod
    def _is_executable(data: dict[str, Any]) -> bool:
        """Return True if the file event looks like an executable."""
        path = str(
            data.get("path", "") or data.get("file_path", "")
        )
        path_lower = path.lower()
        executable_exts = (
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
            ".vbs", ".js", ".hta", ".msi",
        )
        return any(path_lower.endswith(ext) for ext in executable_exts)

    @staticmethod
    def _is_credential_path(data: dict[str, Any]) -> bool:
        """Return True if the file path matches a browser credential DB."""
        path = str(
            data.get("path", "") or data.get("file_path", "")
        ).lower()
        return any(cred in path for cred in _BROWSER_CREDENTIAL_PATHS)

    @staticmethod
    def _is_suspicious_origin(data: dict[str, Any]) -> bool:
        """Return True if a process is unsigned or from a temp directory."""
        sig = str(data.get("signature_status", "")).lower()
        is_unsigned = sig in ("unsigned", "invalid", "")

        path = str(
            data.get("path", "") or data.get("exe", "")
        ).lower()
        temp_indicators = (
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
            "\\downloads\\", "%temp%", "%tmp%",
        )
        is_temp = any(t in path for t in temp_indicators)

        return is_unsigned or is_temp

    @staticmethod
    def _is_persistence_path(data: dict[str, Any]) -> bool:
        """Return True if a file write targets a persistence location."""
        path = str(
            data.get("path", "") or data.get("file_path", "")
        ).lower()
        return any(p in path for p in _PERSISTENCE_INDICATORS)

    @staticmethod
    def _is_persistence_event(data: dict[str, Any]) -> bool:
        """Return True if a log event indicates persistence activity."""
        etype = str(data.get("event_type", "")).lower()
        eid = str(data.get("event_id_win", ""))

        # Registry writes to Run keys
        reg_key = str(data.get("registry_key", "")).lower()
        if any(p in reg_key for p in _PERSISTENCE_INDICATORS):
            return True

        # Scheduled task creation events
        if eid in ("4698",) or "scheduled_task" in etype:
            return True

        # Service installation events
        if eid in ("7045", "4697") or "service_install" in etype:
            return True

        return False

    @staticmethod
    def _has_encoded_flag(data: dict[str, Any]) -> bool:
        """Return True if the command line contains an encoded flag."""
        cmdline = str(
            data.get("cmdline", "")
            or data.get("command_line", "")
        ).lower()
        encoded_flags = ("-enc ", "-encodedcommand ", "-ec ")
        return any(flag in cmdline for flag in encoded_flags)

    @staticmethod
    def _has_entropy_increase(data: dict[str, Any]) -> bool:
        """Return True if file data shows an entropy increase."""
        try:
            before = float(data.get("entropy_before", 0) or 0)
            after = float(data.get("entropy_after", 0) or 0)
            if after > before and after > 6.0:
                return True
        except (TypeError, ValueError):
            pass
        return bool(data.get("entropy_increased"))

    @staticmethod
    def _is_external_connection(data: dict[str, Any]) -> bool:
        """Return True if a network node is an external connection."""
        dst_ip = str(
            data.get("dst_ip", "") or data.get("remote_ip", "")
        )
        if not dst_ip:
            return True  # Unknown destination is suspicious

        # RFC-1918 private ranges and localhost are internal
        private_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "0.", "::1",
            "fe80:", "fd",
        )
        return not any(dst_ip.startswith(p) for p in private_prefixes)
