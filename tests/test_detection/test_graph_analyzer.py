"""Tests for the Context Graph Analyzer detection engine."""

from __future__ import annotations

import time

import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.detection.graph_analyzer import (
    ATTACK_CHAINS,
    DEFAULT_WINDOW_SECONDS,
    ChainMatch,
    ContextGraph,
    GraphAnalyzer,
    GraphEdge,
    GraphNode,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_node(
    node_id: str,
    node_type: str,
    data: dict | None = None,
    timestamp: float | None = None,
) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        node_type=node_type,
        data=data or {},
        timestamp=timestamp or time.time(),
    )


def _make_edge(
    source_id: str,
    target_id: str,
    edge_type: str,
    data: dict | None = None,
    timestamp: float | None = None,
) -> GraphEdge:
    return GraphEdge(
        source_id=source_id,
        target_id=target_id,
        edge_type=edge_type,
        data=data or {},
        timestamp=timestamp or time.time(),
    )


def _make_event(
    event_type: str,
    sensor: SensorType,
    severity: Severity = Severity.INFO,
    data: dict | None = None,
    timestamp: float | None = None,
) -> AegisEvent:
    return AegisEvent(
        sensor=sensor,
        event_type=event_type,
        severity=severity,
        data=data or {},
        timestamp=timestamp or time.time(),
    )


# ===========================================================================
# ContextGraph tests
# ===========================================================================

class TestContextGraphInit:
    def test_default_window(self) -> None:
        g = ContextGraph()
        assert g.window_seconds == DEFAULT_WINDOW_SECONDS

    def test_custom_window(self) -> None:
        g = ContextGraph(window_seconds=600.0)
        assert g.window_seconds == 600.0

    def test_starts_empty(self) -> None:
        g = ContextGraph()
        assert g.node_count == 0
        assert g.edge_count == 0


class TestContextGraphNodes:
    def test_add_and_get_node(self) -> None:
        g = ContextGraph()
        node = _make_node("n1", "process", {"name": "test.exe"})
        g.add_node(node)
        assert g.get_node("n1") is node

    def test_get_node_missing_returns_none(self) -> None:
        g = ContextGraph()
        assert g.get_node("nonexistent") is None

    def test_add_node_with_pid_creates_mapping(self) -> None:
        g = ContextGraph()
        node = _make_node("proc1", "process", {"pid": 1234})
        g.add_node(node)
        assert g._pid_to_node["1234"] == "proc1"

    def test_add_node_without_pid_no_mapping(self) -> None:
        g = ContextGraph()
        node = _make_node("file1", "file", {"path": "c:\\test.txt"})
        g.add_node(node)
        assert len(g._pid_to_node) == 0

    def test_get_nodes_by_type_filters(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("p1", "process"))
        g.add_node(_make_node("p2", "process"))
        g.add_node(_make_node("f1", "file"))
        g.add_node(_make_node("n1", "network"))

        procs = g.get_nodes_by_type("process")
        assert len(procs) == 2
        assert all(n.node_type == "process" for n in procs)

    def test_get_nodes_by_type_empty(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("p1", "process"))
        assert g.get_nodes_by_type("network") == []

    def test_node_count(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("a", "process"))
        g.add_node(_make_node("b", "file"))
        assert g.node_count == 2


class TestContextGraphEdges:
    def test_add_edge_and_get_neighbors(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("src", "process"))
        target = _make_node("tgt", "file")
        g.add_node(target)
        g.add_edge(_make_edge("src", "tgt", "modified"))

        neighbors = g.get_neighbors("src")
        assert len(neighbors) == 1
        assert neighbors[0].node_id == "tgt"

    def test_get_neighbors_with_edge_type_filter(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("src", "process"))
        g.add_node(_make_node("t1", "file"))
        g.add_node(_make_node("t2", "network"))
        g.add_edge(_make_edge("src", "t1", "modified"))
        g.add_edge(_make_edge("src", "t2", "opened"))

        modified = g.get_neighbors("src", edge_type="modified")
        assert len(modified) == 1
        assert modified[0].node_id == "t1"

        opened = g.get_neighbors("src", edge_type="opened")
        assert len(opened) == 1
        assert opened[0].node_id == "t2"

    def test_get_neighbors_no_match(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("src", "process"))
        assert g.get_neighbors("src") == []

    def test_edge_count(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("a", "process"))
        g.add_node(_make_node("b", "file"))
        g.add_node(_make_node("c", "network"))
        g.add_edge(_make_edge("a", "b", "modified"))
        g.add_edge(_make_edge("a", "c", "opened"))
        assert g.edge_count == 2


class TestContextGraphPruning:
    def test_prune_removes_old_nodes(self) -> None:
        g = ContextGraph(window_seconds=60.0)
        now = time.time()
        old_node = _make_node("old", "process", timestamp=now - 120)
        g.add_node(old_node)
        removed = g.prune(now=now)
        assert removed == 1
        assert g.get_node("old") is None

    def test_prune_keeps_recent_nodes(self) -> None:
        g = ContextGraph(window_seconds=60.0)
        now = time.time()
        recent = _make_node("recent", "process", timestamp=now - 10)
        g.add_node(recent)
        removed = g.prune(now=now)
        assert removed == 0
        assert g.get_node("recent") is not None

    def test_prune_returns_count(self) -> None:
        g = ContextGraph(window_seconds=60.0)
        now = time.time()
        g.add_node(_make_node("a", "process", timestamp=now - 100))
        g.add_node(_make_node("b", "file", timestamp=now - 100))
        g.add_node(_make_node("c", "network", timestamp=now - 10))
        removed = g.prune(now=now)
        assert removed == 2
        assert g.node_count == 1

    def test_prune_removes_edges_with_stale_nodes(self) -> None:
        g = ContextGraph(window_seconds=60.0)
        now = time.time()
        g.add_node(_make_node("a", "process", timestamp=now - 100))
        g.add_node(_make_node("b", "file", timestamp=now - 10))
        g.add_edge(_make_edge("a", "b", "modified", timestamp=now - 100))
        g.prune(now=now)
        assert g.edge_count == 0

    def test_prune_cleans_pid_map(self) -> None:
        g = ContextGraph(window_seconds=60.0)
        now = time.time()
        g.add_node(_make_node("p", "process", {"pid": 999}, timestamp=now - 120))
        assert "999" in g._pid_to_node
        g.prune(now=now)
        assert "999" not in g._pid_to_node


class TestContextGraphClear:
    def test_clear_removes_everything(self) -> None:
        g = ContextGraph()
        g.add_node(_make_node("a", "process", {"pid": 10}))
        g.add_node(_make_node("b", "file"))
        g.add_edge(_make_edge("a", "b", "modified"))
        g.clear()
        assert g.node_count == 0
        assert g.edge_count == 0
        assert len(g._pid_to_node) == 0


class TestContextGraphIngestEvent:
    def test_ingest_process_event(self) -> None:
        g = ContextGraph()
        event = _make_event("process_start", SensorType.PROCESS, data={"pid": 100})
        node = g.ingest_event(event)
        assert node.node_type == "process"
        assert g.node_count == 1

    def test_ingest_file_event(self) -> None:
        g = ContextGraph()
        event = _make_event("file_write", SensorType.FILE)
        node = g.ingest_event(event)
        assert node.node_type == "file"

    def test_ingest_network_event(self) -> None:
        g = ContextGraph()
        event = _make_event("connection", SensorType.NETWORK)
        node = g.ingest_event(event)
        assert node.node_type == "network"

    def test_ingest_eventlog_event(self) -> None:
        g = ContextGraph()
        event = _make_event("logon", SensorType.EVENTLOG)
        node = g.ingest_event(event)
        assert node.node_type == "log"

    def test_ingest_unknown_sensor_defaults_to_log(self) -> None:
        g = ContextGraph()
        event = _make_event("hw_change", SensorType.HARDWARE)
        node = g.ingest_event(event)
        assert node.node_type == "log"

    def test_ingest_links_child_to_parent_via_pid(self) -> None:
        g = ContextGraph()
        parent_evt = _make_event(
            "process_start", SensorType.PROCESS, data={"pid": 100}
        )
        g.ingest_event(parent_evt)

        child_evt = _make_event(
            "process_start", SensorType.PROCESS,
            data={"pid": 200, "ppid": 100},
        )
        g.ingest_event(child_evt)
        assert g.edge_count >= 1


# ===========================================================================
# GraphAnalyzer basic tests
# ===========================================================================

class TestGraphAnalyzerInit:
    def test_default_graph(self) -> None:
        analyzer = GraphAnalyzer()
        assert analyzer.graph is not None
        assert analyzer.graph.window_seconds == DEFAULT_WINDOW_SECONDS

    def test_custom_graph(self) -> None:
        custom = ContextGraph(window_seconds=120.0)
        analyzer = GraphAnalyzer(graph=custom)
        assert analyzer.graph is custom

    def test_ingest_delegates_to_graph(self) -> None:
        analyzer = GraphAnalyzer()
        event = _make_event("test", SensorType.PROCESS, data={"pid": 1})
        node = analyzer.ingest(event)
        assert analyzer.graph.node_count == 1
        assert node.node_type == "process"

    def test_analyze_empty_graph(self) -> None:
        analyzer = GraphAnalyzer()
        matches = analyzer.analyze()
        assert matches == []


# ===========================================================================
# Attack chain detection tests
# ===========================================================================

class TestDriveByDownload:
    def test_detects_browser_download_execute(self) -> None:
        g = ContextGraph()
        now = time.time()

        browser = _make_node(
            "browser", "process",
            {"name": "chrome.exe"},
            timestamp=now,
        )
        g.add_node(browser)

        downloaded_file = _make_node(
            "file_dl", "file",
            {"path": "c:\\users\\test\\downloads\\malware.exe"},
            timestamp=now,
        )
        g.add_node(downloaded_file)
        g.add_edge(_make_edge("browser", "file_dl", "modified", timestamp=now))

        executed = _make_node(
            "exec_proc", "process",
            {"name": "c:\\users\\test\\downloads\\malware.exe"},
            timestamp=now,
        )
        g.add_node(executed)

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "drive_by_download"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.85
        assert "T1189" in match.mitre_ids
        assert match.severity == "CRITICAL"


class TestCredentialTheft:
    def test_detects_cred_access_and_exfil(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node(
            "stealer", "process",
            {"name": "stealer.exe"},
            timestamp=now,
        )
        g.add_node(proc)

        cred_file = _make_node(
            "cred", "file",
            {"path": "c:\\users\\test\\appdata\\local\\google"
                     "\\chrome\\user data\\default\\login data"},
            timestamp=now,
        )
        g.add_node(cred_file)
        g.add_edge(_make_edge("stealer", "cred", "modified", timestamp=now))

        net = _make_node(
            "net_conn", "network",
            {"dst_ip": "45.33.32.156"},
            timestamp=now,
        )
        g.add_node(net)
        g.add_edge(_make_edge("stealer", "net_conn", "opened", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "credential_theft"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.9
        assert "T1555" in match.mitre_ids
        assert match.severity == "CRITICAL"

    def test_ignores_browser_reading_own_creds(self) -> None:
        g = ContextGraph()
        now = time.time()

        browser = _make_node(
            "browser", "process",
            {"name": "chrome.exe"},
            timestamp=now,
        )
        g.add_node(browser)

        cred_file = _make_node(
            "cred", "file",
            {"path": "c:\\users\\test\\appdata\\local\\google\\chrome\\login data"},
            timestamp=now,
        )
        g.add_node(cred_file)
        g.add_edge(_make_edge("browser", "cred", "modified", timestamp=now))

        net = _make_node("net", "network", {"dst_ip": "8.8.8.8"}, timestamp=now)
        g.add_node(net)
        g.add_edge(_make_edge("browser", "net", "opened", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()
        cred_matches = [m for m in matches if m.chain_name == "credential_theft"]
        assert len(cred_matches) == 0


class TestRansomware:
    def test_detects_mass_file_modification(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node(
            "ransom", "process",
            {"name": "locker.exe"},
            timestamp=now,
        )
        g.add_node(proc)

        for i in range(50):
            fnode = _make_node(
                f"f_{i}", "file",
                {"path": f"c:\\docs\\file{i}.docx.encrypted"},
                timestamp=now + i * 0.1,  # all within 5 seconds
            )
            g.add_node(fnode)
            g.add_edge(_make_edge("ransom", f"f_{i}", "modified", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "ransomware"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.95
        assert "T1486" in match.mitre_ids
        assert match.severity == "CRITICAL"

    def test_below_threshold_no_match(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node("p", "process", {"name": "app.exe"}, timestamp=now)
        g.add_node(proc)

        for i in range(10):  # Only 10 files, below threshold of 50
            fnode = _make_node(f"f{i}", "file", timestamp=now)
            g.add_node(fnode)
            g.add_edge(_make_edge("p", f"f{i}", "modified", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()
        assert not [m for m in matches if m.chain_name == "ransomware"]


class TestPersistenceInstallation:
    def test_detects_unsigned_process_startup_write(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node(
            "suspicious", "process",
            {
                "name": "implant.exe",
                "signature_status": "unsigned",
                "path": "c:\\temp\\implant.exe",
            },
            timestamp=now,
        )
        g.add_node(proc)

        startup_file = _make_node(
            "startup_f", "file",
            {
                "path": "c:\\users\\test\\appdata\\roaming\\microsoft\\"
                        "windows\\start menu\\programs\\startup\\implant.lnk",
            },
            timestamp=now,
        )
        g.add_node(startup_file)
        g.add_edge(_make_edge("suspicious", "startup_f", "modified", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "persistence_installation"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.8
        assert "T1547.001" in match.mitre_ids
        assert match.severity == "HIGH"


class TestFilelessAttack:
    def test_detects_encoded_powershell_with_network(self) -> None:
        g = ContextGraph()
        now = time.time()

        parent = _make_node(
            "parent", "process",
            {"name": "winword.exe"},
            timestamp=now,
        )
        g.add_node(parent)

        ps = _make_node(
            "ps_child", "process",
            {
                "name": "powershell.exe",
                "cmdline": "powershell.exe -enc SQBFAFgA...",
            },
            timestamp=now,
        )
        g.add_node(ps)
        g.add_edge(_make_edge("parent", "ps_child", "spawned", timestamp=now))

        net = _make_node(
            "c2_conn", "network",
            {"dst_ip": "185.220.101.1"},
            timestamp=now,
        )
        g.add_node(net)
        g.add_edge(_make_edge("ps_child", "c2_conn", "opened", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "fileless_attack"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.85
        assert "T1059.001" in match.mitre_ids
        assert match.severity == "CRITICAL"

    def test_fileless_with_disk_write_lowers_confidence(self) -> None:
        g = ContextGraph()
        now = time.time()

        parent = _make_node("parent", "process", {"name": "cmd.exe"}, timestamp=now)
        g.add_node(parent)

        ps = _make_node(
            "ps", "process",
            {"name": "powershell.exe", "cmdline": "powershell -enc AAAA"},
            timestamp=now,
        )
        g.add_node(ps)
        g.add_edge(_make_edge("parent", "ps", "spawned", timestamp=now))

        net = _make_node("net", "network", {"dst_ip": "8.8.4.4"}, timestamp=now)
        g.add_node(net)
        g.add_edge(_make_edge("ps", "net", "opened", timestamp=now))

        disk_file = _make_node("disk", "file", {"path": "c:\\tmp\\out.txt"}, timestamp=now)
        g.add_node(disk_file)
        g.add_edge(_make_edge("ps", "disk", "modified", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "fileless_attack"]
        assert len(chain_matches) >= 1
        assert chain_matches[0].confidence == pytest.approx(0.85 * 0.7)


class TestLateralMovement:
    def test_detects_failed_auth_then_success_then_service(self) -> None:
        g = ContextGraph()
        now = time.time()

        # 3 failed logins
        for i in range(3):
            fl = _make_node(
                f"fail_{i}", "log",
                {"event_type": "failed_login"},
                timestamp=now + i,
            )
            g.add_node(fl)

        # 1 successful login
        success = _make_node(
            "success_login", "log",
            {"event_type": "successful_login"},
            timestamp=now + 4,
        )
        g.add_node(success)

        # 1 service install
        svc = _make_node(
            "svc_install", "log",
            {"event_type": "service_install"},
            timestamp=now + 5,
        )
        g.add_node(svc)

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "lateral_movement"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.8
        assert "T1021" in match.mitre_ids
        assert match.severity == "HIGH"

    def test_insufficient_failures_no_match(self) -> None:
        g = ContextGraph()
        now = time.time()

        # Only 2 failed logins (need at least 3)
        for i in range(2):
            g.add_node(_make_node(
                f"fail_{i}", "log",
                {"event_type": "failed_login"},
                timestamp=now + i,
            ))

        g.add_node(_make_node(
            "ok", "log",
            {"event_type": "successful_login"},
            timestamp=now + 3,
        ))
        g.add_node(_make_node(
            "svc", "log",
            {"event_type": "service_install"},
            timestamp=now + 4,
        ))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()
        assert not [m for m in matches if m.chain_name == "lateral_movement"]


class TestDataExfiltration:
    def test_detects_mass_file_read_with_external_conn(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node(
            "exfil", "process",
            {"name": "data_stealer.exe"},
            timestamp=now,
        )
        g.add_node(proc)

        for i in range(20):
            fnode = _make_node(
                f"doc_{i}", "file",
                {"path": f"c:\\sensitive\\report{i}.pdf"},
                timestamp=now,
            )
            g.add_node(fnode)
            g.add_edge(_make_edge("exfil", f"doc_{i}", "modified", timestamp=now))

        net = _make_node(
            "ext_net", "network",
            {"dst_ip": "203.0.113.50", "bytes_sent": 60_000_000},
            timestamp=now,
        )
        g.add_node(net)
        g.add_edge(_make_edge("exfil", "ext_net", "opened", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "data_exfiltration"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.85
        assert "T1041" in match.mitre_ids
        assert match.severity == "CRITICAL"

    def test_low_volume_exfil_lowers_confidence(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node("p", "process", {"name": "app.exe"}, timestamp=now)
        g.add_node(proc)

        for i in range(20):
            f = _make_node(f"f{i}", "file", timestamp=now)
            g.add_node(f)
            g.add_edge(_make_edge("p", f"f{i}", "modified", timestamp=now))

        net = _make_node(
            "net", "network",
            {"dst_ip": "1.2.3.4", "bytes_sent": 1000},  # small
            timestamp=now,
        )
        g.add_node(net)
        g.add_edge(_make_edge("p", "net", "opened", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "data_exfiltration"]
        assert len(chain_matches) >= 1
        assert chain_matches[0].confidence == pytest.approx(0.85 * 0.6)


class TestDllInjection:
    def test_detects_api_call_sequence(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node(
            "injector", "process",
            {"name": "injector.exe"},
            timestamp=now,
        )
        g.add_node(proc)

        log_va = _make_node(
            "log_va", "log",
            {"api_call": "VirtualAllocEx"},
            timestamp=now,
        )
        g.add_node(log_va)
        g.add_edge(_make_edge("injector", "log_va", "triggered", timestamp=now))

        log_wpm = _make_node(
            "log_wpm", "log",
            {"api_call": "WriteProcessMemory"},
            timestamp=now,
        )
        g.add_node(log_wpm)
        g.add_edge(_make_edge("injector", "log_wpm", "triggered", timestamp=now))

        log_crt = _make_node(
            "log_crt", "log",
            {"api_call": "CreateRemoteThread"},
            timestamp=now,
        )
        g.add_node(log_crt)
        g.add_edge(_make_edge("injector", "log_crt", "triggered", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "dll_injection"]
        assert len(chain_matches) >= 1
        match = chain_matches[0]
        assert match.confidence == 0.9
        assert "T1055.001" in match.mitre_ids
        assert match.severity == "CRITICAL"

    def test_partial_api_sequence_no_match(self) -> None:
        g = ContextGraph()
        now = time.time()

        proc = _make_node("p", "process", {"name": "app.exe"}, timestamp=now)
        g.add_node(proc)

        # Only VirtualAllocEx and WriteProcessMemory -- missing CreateRemoteThread
        g.add_node(_make_node("l1", "log", {"api_call": "VirtualAllocEx"}, timestamp=now))
        g.add_edge(_make_edge("p", "l1", "triggered", timestamp=now))
        g.add_node(_make_node("l2", "log", {"api_call": "WriteProcessMemory"}, timestamp=now))
        g.add_edge(_make_edge("p", "l2", "triggered", timestamp=now))

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()
        assert not [m for m in matches if m.chain_name == "dll_injection"]

    def test_sysmon_event_8_path_b(self) -> None:
        g = ContextGraph()
        now = time.time()

        sysmon_log = _make_node(
            "sysmon8", "log",
            {
                "event_id_win": "8",
                "source_image": "c:\\malware\\inject.exe",
                "target_image": "c:\\windows\\system32\\svchost.exe",
            },
            timestamp=now,
        )
        g.add_node(sysmon_log)

        analyzer = GraphAnalyzer(graph=g)
        matches = analyzer.analyze()

        chain_matches = [m for m in matches if m.chain_name == "dll_injection"]
        assert len(chain_matches) >= 1
        assert "T1055.001" in chain_matches[0].mitre_ids


# ===========================================================================
# ChainMatch and ATTACK_CHAINS structure tests
# ===========================================================================

class TestChainMatchStructure:
    def test_chain_match_fields(self) -> None:
        cm = ChainMatch(
            chain_name="test_chain",
            confidence=0.9,
            mitre_ids=["T1234"],
            matched_nodes=["n1", "n2"],
            description="test",
            severity="HIGH",
            timestamp=123.0,
        )
        assert cm.chain_name == "test_chain"
        assert cm.confidence == 0.9
        assert cm.mitre_ids == ["T1234"]
        assert cm.matched_nodes == ["n1", "n2"]
        assert cm.description == "test"
        assert cm.severity == "HIGH"
        assert cm.timestamp == 123.0

    def test_chain_match_defaults(self) -> None:
        cm = ChainMatch(chain_name="x", confidence=0.5)
        assert cm.mitre_ids == []
        assert cm.matched_nodes == []
        assert cm.description == ""
        assert cm.severity == "HIGH"
        assert cm.timestamp == 0.0


class TestAttackChainsDict:
    def test_has_eight_entries(self) -> None:
        assert len(ATTACK_CHAINS) == 8

    def test_expected_chain_names(self) -> None:
        expected = {
            "drive_by_download",
            "credential_theft",
            "ransomware",
            "persistence_installation",
            "fileless_attack",
            "lateral_movement",
            "data_exfiltration",
            "dll_injection",
        }
        assert set(ATTACK_CHAINS.keys()) == expected

    @pytest.mark.parametrize("chain_name", list(ATTACK_CHAINS.keys()))
    def test_chain_has_required_fields(self, chain_name: str) -> None:
        chain = ATTACK_CHAINS[chain_name]
        assert "mitre_ids" in chain
        assert isinstance(chain["mitre_ids"], list)
        assert len(chain["mitre_ids"]) > 0
        assert "confidence" in chain
        assert 0.0 < chain["confidence"] <= 1.0
        assert "severity" in chain
        assert chain["severity"] in ("HIGH", "CRITICAL")
        assert "stages" in chain
        assert isinstance(chain["stages"], list)


class TestDefaultWindowConstant:
    def test_value_is_1800(self) -> None:
        assert DEFAULT_WINDOW_SECONDS == 1800.0
