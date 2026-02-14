# Aegis — Autonomous AI Security Defense System

## Design Document
**Date:** 2026-02-14
**Status:** Approved
**Target Platform:** Windows 10/11 (x64)
**Language:** Python 3.11+
**License:** Open Source (MIT)

---

## 1. Vision

Aegis is an all-in-one, autonomous AI security defense system for Windows PCs that surpasses existing free and commercial tools by combining:

- **7 independent sensor modules** covering every attack surface (network, process, file, logs, threat intel, USB/hardware, clipboard/screen)
- **6 detection engines** running in parallel (rules, statistical anomaly, deep anomaly, temporal sequence, URL classification, context graph analysis)
- **A rolling context graph** that correlates events across all sensors to detect multi-stage attack chains — the feature that makes Aegis enterprise-grade
- **Smart alerting** with confidence scores, plain-English explanations, MITRE ATT&CK mapping, and learning from user feedback
- **A polished desktop application** with system tray integration, real-time dashboard, and one-click response actions

**Design philosophy:**
- Local-first, cloud-optional (core detection works fully offline)
- Alert and recommend (user stays in control, Aegis never takes drastic action without approval)
- Open source product quality (clean architecture, plugin system, documentation)
- Security tool that protects itself (self-protection module)

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     AEGIS DESKTOP APP                        │
│                   (PyQt6 / PySide6)                          │
│  ┌───────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │System Tray│  │Toast Alerts  │  │  Dashboard Window     │ │
│  │ Icon      │  │(win10toast)  │  │  - Threat Feed        │ │
│  │ G / Y / R │  │              │  │  - Context Graph Viz  │ │
│  └───────────┘  └──────────────┘  │  - Sensor Status      │ │
│                                    │  - Historical Charts  │ │
│                                    │  - Alert Management   │ │
│                                    └───────────────────────┘ │
└──────────────────────┬───────────────────────────────────────┘
                       │ reads alerts & events
         ┌─────────────▼──────────────────┐
         │        EVENT ENGINE            │
         │   ┌─────────────────────────┐  │
         │   │  ZeroMQ Pub/Sub Bus     │  │
         │   └─────────────────────────┘  │
         │   ┌─────────────────────────┐  │
         │   │  Context Graph          │  │
         │   │  (in-memory, rolling    │  │
         │   │   30-min window)        │  │
         │   └─────────────────────────┘  │
         │   ┌─────────────────────────┐  │
         │   │  SQLite Event Store     │  │
         │   │  (persistent history)   │  │
         │   └─────────────────────────┘  │
         └──┬───┬───┬───┬───┬───┬───┬────┘
            │   │   │   │   │   │   │
         ┌──▼┐┌─▼─┐┌▼──┐┌──▼┐┌─▼─┐┌▼──┐┌──▼──┐
         │NET││PRO││FIM││LOG││TI ││USB││CLIP │
         │   ││CSS││   ││   ││   ││HW ││SCRN │
         └───┘└───┘└───┘└───┘└───┘└───┘└─────┘
         SENSOR MODULES (7 independent processes)
            │   │   │   │   │   │   │
            └───┴───┴───┴───┴───┴───┘
                       │ events flow to
         ┌─────────────▼──────────────────┐
         │      DETECTION ENGINES         │
         │      (parallel workers)        │
         │                                │
         │  1. Rule Engine (YARA/Sigma)   │
         │  2. Isolation Forest           │
         │  3. Autoencoder                │
         │  4. LSTM Sequence Analyzer     │
         │  5. URL/Phishing Classifier    │
         │  6. Context Graph Analyzer     │
         └─────────────┬─────────────────┘
                       │
         ┌─────────────▼──────────────────┐
         │      RESPONSE MANAGER          │
         │                                │
         │  - Alert scoring & ranking     │
         │  - Deduplication               │
         │  - Plain-English generation    │
         │  - Action recommendations      │
         │  - User feedback learning      │
         │  - Forensic logging            │
         └────────────────────────────────┘

         ┌────────────────────────────────┐
         │      SELF-PROTECTION MODULE    │
         │                                │
         │  - Process watchdog service    │
         │  - Config file integrity       │
         │  - Anti-tamper detection       │
         │  - Auto-restart on crash       │
         └────────────────────────────────┘
```

### 2.2 Inter-Process Communication

- **ZeroMQ PUB/SUB** for sensor → event engine communication
  - Each sensor publishes to a topic (e.g., `sensor.network`, `sensor.process`)
  - Detection engines subscribe to relevant topics
  - Non-blocking, async, handles backpressure gracefully
- **ZeroMQ REQ/REP** for UI → event engine queries (fetch alerts, historical data)
- **SQLite** (WAL mode) for persistent storage — events, alerts, baselines, user preferences
- **Shared memory** (via `multiprocessing.shared_memory`) for the context graph — sub-millisecond reads by detection engines

### 2.3 Process Model

```
aegis-service.exe          (Windows Service — watchdog, auto-start on boot)
  ├── aegis-engine.exe     (Event Engine — central coordinator)
  ├── aegis-net.exe        (Network Sensor)
  ├── aegis-proc.exe       (Process Watchdog)
  ├── aegis-fim.exe        (File Integrity Monitor)
  ├── aegis-log.exe        (Windows Event Log Analyzer)
  ├── aegis-ti.exe         (Threat Intelligence Feed)
  ├── aegis-hw.exe         (USB & Hardware Monitor)
  ├── aegis-clip.exe       (Clipboard & Screen Monitor)
  ├── aegis-detect.exe     (Detection Engine Worker Pool)
  └── aegis-ui.exe         (Desktop Application — launched by user)
```

Each process is independently restartable. The service monitors all child processes and restarts any that crash within 5 seconds.

---

## 3. Sensor Modules (Data Collection Layer)

### 3.1 Network Sensor (`aegis-net`)

**Libraries:** `scapy`, `pyshark`

**Data captured:**
- Every inbound/outbound connection: source/dest IP, port, protocol, packet size, timing
- DNS queries and responses (domain → IP mapping)
- TLS handshake metadata (JA3/JA3S fingerprints for encrypted traffic profiling)
- HTTP headers (for unencrypted traffic)

**Feature extraction (per 30-second window):**
- `packets_per_sec` — total packet rate
- `bytes_per_sec` — bandwidth consumption
- `unique_dest_ips` — connection fan-out
- `unique_dest_ports` — port diversity
- `port_entropy` — randomness of destination ports (high = scan)
- `protocol_distribution` — TCP/UDP/ICMP/other ratios
- `dns_query_rate` — DNS queries per second
- `avg_packet_size` — mean packet size
- `connection_duration_stats` — min/max/mean/std of connection durations
- `new_destination_rate` — IPs contacted for the first time

**Wi-Fi layer monitoring:**
- ARP table snapshots every 10 seconds — detect ARP spoofing
- DHCP server tracking — detect rogue DHCP servers
- SSID monitoring — detect evil twin access points

**Unique feature — Connection Reputation Scores:**
Every IP/domain gets a rolling trust score (0-100):
- Starts at 50 (unknown)
- +points for: long history, consistent behavior, clean threat intel, valid TLS cert
- -points for: first contact, unusual port, threat intel match, high-entropy domain name, geolocation anomaly
- Score persists in SQLite, updated with each interaction

**Detects:** Port scans, DDoS, DNS tunneling, C2 beaconing, data exfiltration, ARP spoofing, evil twins, rogue DHCP.

### 3.2 Process Watchdog (`aegis-proc`)

**Libraries:** `psutil`, `python-evtx` (for Sysmon event parsing)

**Data captured:**
- Full process tree (parent → child relationships)
- Command-line arguments for every process
- DLL loads per process
- CPU/memory/disk/network usage per process
- Open file handles and registry key access
- Digital signature status (signed/unsigned/invalid)
- File path and hash of executable

**Feature extraction (per process, updated every 5 seconds):**
- `cmdline_entropy` — Shannon entropy of command line (obfuscated commands = high entropy)
- `child_process_count` — number of child processes spawned
- `network_connection_count` — active connections from this process
- `file_handle_count` — open file handles
- `cpu_deviation` — deviation from this process's historical baseline
- `memory_deviation` — same for memory
- `signature_status` — signed/unsigned/invalid
- `lineage_depth` — how deep in the process tree (Word→cmd→PowerShell→whoami = depth 4)
- `is_masquerading` — name matches system binary but path doesn't match expected location

**Unique feature — Process DNA Profiling:**
Every process builds a behavioral fingerprint over time:
- What files it typically accesses
- What network connections it typically makes
- What registry keys it typically reads/writes
- What child processes it typically spawns
- What DLLs it typically loads

New processes are compared against known-good profiles. A process named `svchost.exe` running from `C:\Users\Temp\` instead of `C:\Windows\System32\` with network connections to an unknown IP gets flagged instantly with high confidence.

**Detects:** Malicious process chains, DLL injection, privilege escalation, crypto miners, process masquerading, LOLBin abuse (living-off-the-land binaries).

### 3.3 File Integrity Monitor (`aegis-fim`)

**Libraries:** `watchdog`, `hashlib`

**Monitored directories:**
- `C:\Windows\System32\` — system binaries
- `C:\Windows\SysWOW64\` — 32-bit system binaries
- `C:\Program Files\` and `C:\Program Files (x86)\` — installed applications
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` — user startup
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\` — all-users startup
- `%USERPROFILE%\` — user home directory (configurable depth)
- Browser profile directories (Chrome, Firefox, Edge credential stores)
- Aegis's own installation directory (self-protection)

**Data captured:**
- File creation, modification, deletion, rename events
- SHA-256 hash before and after modification
- Process that performed the modification (via context graph correlation)
- File entropy before and after (detects encryption)

**Feature extraction (per 60-second window):**
- `files_changed_per_minute` — change velocity
- `file_types_changed` — distribution of file extensions affected
- `entropy_increase_rate` — how fast file entropy is increasing (encryption indicator)
- `critical_dir_changes` — changes in system-critical directories
- `canary_status` — status of deployed canary files

**Unique feature — Ransomware Tripwire System:**
Aegis deploys hidden canary files in:
- Desktop, Documents, Pictures, Videos, Downloads
- Key system directories
- External drives when connected

Canary files are:
- Named to be alphabetically first (ransomware typically processes alphabetically)
- Diverse types (.docx, .xlsx, .pdf, .jpg) to match ransomware targeting
- Monitored continuously — any modification = instant CRITICAL alert
- Alert fires BEFORE real user files are encrypted

**Unique feature — Browser Protection:**
- Monitors Chrome/Firefox/Edge extension directories for new installs or permission changes
- Watches browser credential database files — alerts if any non-browser process accesses them
- Hashes newly downloaded files and checks against threat intel cache

**Detects:** Ransomware, unauthorized system file modification, persistence mechanisms, browser credential theft, malicious extension installation.

### 3.4 Windows Event Log Analyzer (`aegis-log`)

**Libraries:** `pywin32` (win32evtlog) for live subscription, `python-evtx` for parsing

**Event sources monitored:**
| Log | Key Event IDs | Purpose |
|-----|---------------|---------|
| Security | 4624, 4625 | Logon success/failure |
| Security | 4648 | Explicit credential logon |
| Security | 4672 | Special privileges assigned |
| Security | 4688 | Process creation (with command line) |
| Security | 4697 | Service installation |
| Security | 4720, 4726 | User account created/deleted |
| Security | 4732 | Member added to security group |
| System | 7045 | New service installed |
| PowerShell | 4104 | Script block logging |
| Sysmon | 1 | Process creation (detailed) |
| Sysmon | 3 | Network connection |
| Sysmon | 7 | Image loaded (DLL) |
| Sysmon | 8 | CreateRemoteThread (injection) |
| Sysmon | 11 | File creation |
| Sysmon | 12, 13 | Registry modification |
| Sysmon | 22 | DNS query |

**Feature extraction:**
- `failed_login_rate` — failed logins per minute (brute force indicator)
- `privilege_escalation_events` — count of 4672 events from non-admin processes
- `new_service_count` — services installed in last hour
- `encoded_powershell_count` — PowerShell commands containing `-enc` or Base64
- `remote_thread_count` — CreateRemoteThread events (DLL injection)

**Unique feature — Attack Chain Reconstruction:**
Doesn't just flag individual events. Correlates sequences across time and maps to MITRE ATT&CK:
- "Failed RDP login x50 → successful login → new service installed → outbound connection to unknown IP"
- Assembled into a single narrative alert with technique IDs and kill chain stage

**Detects:** Brute force attacks, lateral movement, persistence via services/scheduled tasks, fileless malware (PowerShell), credential dumping, DLL injection.

### 3.5 Threat Intelligence Feed (`aegis-ti`)

**Libraries:** `requests`, `yara-python`

**Sources (all free tiers):**
| Source | Data Type | Update Frequency |
|--------|-----------|------------------|
| VirusTotal | File hashes, URLs, domains | On-demand (API rate limited) |
| AbuseIPDB | Malicious IP addresses | Every 30 minutes |
| PhishTank | Phishing URLs | Every 30 minutes |
| AlienVault OTX | IOCs (IPs, domains, hashes, URLs) | Every 30 minutes |
| MISP community feeds | Structured threat intelligence | Every 60 minutes |
| Emerging Threats | Suricata/Snort rules | Daily |
| YARA community rules | Malware signatures | Daily |
| Sigma rules | Detection rules | Daily |

**Unique feature — Local IOC Cache with Bloom Filters:**
Instead of making API calls for every check (slow, rate-limited):
- Maintains a local bloom filter database of millions of known-bad indicators
- Bloom filter queries take microseconds
- Positive matches are verified against the full IOC database (also local)
- Cloud APIs are only called to confirm true positives and fetch additional context
- Works fully offline — cache is populated when internet is available

**IOC database structure (SQLite):**
```sql
CREATE TABLE ioc_indicators (
    id INTEGER PRIMARY KEY,
    type TEXT,           -- 'ip', 'domain', 'hash', 'url'
    value TEXT,
    source TEXT,         -- 'virustotal', 'abuseipdb', etc.
    severity TEXT,       -- 'low', 'medium', 'high', 'critical'
    first_seen DATETIME,
    last_updated DATETIME,
    metadata TEXT         -- JSON blob with additional context
);
CREATE INDEX idx_ioc_value ON ioc_indicators(type, value);
```

### 3.6 USB & Hardware Monitor (`aegis-hw`)

**Libraries:** `WMI` module, `pywin32`

**Data captured:**
- USB device insertion/removal events (device ID, vendor ID, product ID, serial)
- Device type classification (storage, HID/keyboard, network adapter, composite)
- Driver load events for new hardware

**Detection logic:**
| Threat | Detection Method |
|--------|-----------------|
| Rubber Ducky / BadUSB | New HID device (keyboard) appears that user didn't physically connect — or a "USB storage device" that also registers as a keyboard |
| Unauthorized USB drive | Unknown device ID not in trusted device whitelist |
| Rogue network adapter | New network adapter appears without user action |
| USB drop attack | Storage device with autorun or suspicious file types |

**User whitelist:**
- First run: all currently connected devices are auto-whitelisted
- New devices trigger an alert: "New USB keyboard detected — did you plug this in?"
- User can approve → added to whitelist, or deny → device flagged

### 3.7 Clipboard & Screen Monitor (`aegis-clip`)

**Libraries:** `pywin32` (clipboard monitoring), `psutil` (process screen capture detection)

**Data captured:**
- Clipboard content changes (text only — images ignored for privacy)
- Process that modified the clipboard
- Screen capture API calls by non-whitelisted processes

**Detection logic:**
| Threat | Detection Method |
|--------|-----------------|
| Clipboard hijacking (crypto) | User copies a crypto address → clipboard content changes to a different address without user action |
| Clipboard hijacking (general) | Clipboard content modified by a background process within 500ms of user copy action |
| Screen capture malware | Non-whitelisted process calls PrintWindow, BitBlt, or GDI+ capture APIs |
| Keylogger detection | Process with active keyboard hooks (via GetAsyncKeyState/SetWindowsHookEx) that isn't an input method or accessibility tool |

**Privacy safeguards:**
- Clipboard content is NEVER logged or stored — only change patterns are analyzed
- Screen content is never captured by Aegis itself
- Only the fact that a suspicious process is capturing the screen is logged

---

## 4. Detection Engines

### 4.1 Engine 1: Rule Engine (Signature-Based)

**Technology:** `yara-python` for file/memory rules, custom Sigma rule interpreter

**Rule sources shipped with Aegis:**
- 200+ YARA rules (malware families, packers, exploits)
- 500+ Sigma rules converted to Aegis format (Windows attack techniques)
- Custom Aegis behavioral rules (process chain patterns, registry persistence, etc.)

**Rule format (Aegis Behavioral Rules):**
```yaml
rule: suspicious_process_chain
description: "Office application spawning command interpreter"
severity: high
mitre: T1059
conditions:
  - parent_process.name in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
  - child_process.name in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
action: alert
```

**Performance:** Microsecond-level matching. This is the first gate — known threats are caught before ML even runs.

### 4.2 Engine 2: Isolation Forest (Statistical Anomaly)

**Library:** `scikit-learn`

**Configuration:**
- One model per sensor domain (network, process, file, log)
- `n_estimators=100`, `contamination=0.01`, `max_features=1.0`
- Trained during 7-day baseline period on user's normal behavior
- Retrained weekly with rolling 30-day window

**Input features per domain:**
- Network: 10 features (packets/sec, bytes/sec, unique IPs, port entropy, etc.)
- Process: 8 features (CPU/memory deviation, child count, connection count, etc.)
- File: 5 features (change velocity, entropy increase, type distribution, etc.)
- Log: 6 features (failed login rate, privilege events, service installs, etc.)

**Output:** Anomaly score 0.0 (normal) to 1.0 (extreme outlier)

**Routing:**
- Score < 0.4 → Normal. Log and dismiss.
- Score 0.4-0.6 → Suspicious. Log with elevated priority.
- Score > 0.6 → Anomalous. Forward to Engine 3 (Autoencoder) for verification.

### 4.3 Engine 3: Autoencoder (Deep Anomaly)

**Library:** PyTorch, deployed via ONNX Runtime

**Architecture:**
```
Input(64) → Linear(48) → ReLU → Linear(32) → ReLU → Linear(16) → ReLU
→ Linear(8) [latent space]
→ Linear(16) → ReLU → Linear(32) → ReLU → Linear(48) → ReLU → Output(64)
```

**Training:**
- Trained on normal event feature vectors collected during baseline period
- Loss function: MSE (mean squared error) between input and reconstruction
- Optimizer: Adam, lr=0.001
- Trained for 50 epochs or until convergence

**Inference:**
- Receives only events that scored > 0.6 from Isolation Forest
- Computes reconstruction error
- High error = confirmed anomaly (the autoencoder couldn't reconstruct it as normal)
- Low error = false positive from Isolation Forest (suppress alert)
- Inference time: ~2ms per event via ONNX Runtime (CPU)

### 4.4 Engine 4: LSTM Sequence Analyzer

**Library:** PyTorch, deployed via ONNX Runtime

**Architecture:**
```
Input sequence (20 events) → Embedding(128) → LSTM(hidden=64, layers=2, bidirectional)
→ Attention layer → Dense(32) → Dense(1, sigmoid)
```

**What it analyzes:**
- Ordered sequences of 20 events from the context graph
- Each event is encoded as a feature vector (event type + key attributes)
- Trained on normal event sequences — learns what "normal chains of events" look like

**Detects:**
- C2 beaconing: periodic network callbacks at regular intervals
- Slow brute force: login failures spread across hours
- Multi-stage attacks: sequences that match known attack progression patterns
- Lateral movement: authentication events across multiple systems/accounts

**Unique capability:** This engine reads the context graph. It doesn't see isolated events — it sees narratives connecting processes, network connections, file changes, and log events into coherent stories.

### 4.5 Engine 5: URL/Phishing Classifier

**Library:** `scikit-learn` Random Forest

**Features extracted per URL (22 features):**
- `url_length` — total URL length
- `domain_length` — domain name length
- `subdomain_depth` — number of subdomains
- `path_depth` — number of path segments
- `special_char_count` — count of @, -, _, ~, etc.
- `digit_ratio` — ratio of digits to total characters
- `has_https` — boolean
- `has_ip_address` — domain is raw IP
- `domain_entropy` — Shannon entropy of domain name
- `tld_reputation` — reputation score of TLD (.com vs .xyz vs .tk)
- `query_param_count` — number of URL parameters
- `has_punycode` — internationalized domain name (homograph attack)
- `brand_similarity` — Levenshtein distance to top 100 brands (paypa1.com → paypal.com)
- `domain_age_days` — from local WHOIS cache (if available)
- Plus 8 additional lexical features

**Training:** PhishTank + Kaggle Malicious URLs dataset
**Performance:** <1ms per URL, ~99.5% accuracy on benchmark

### 4.6 Engine 6: Context Graph Analyzer

**Technology:** Custom graph traversal on in-memory context graph

**Context graph structure:**
```
Nodes:
  - Process (pid, name, path, hash, signature, user)
  - NetworkConnection (src_ip, dst_ip, dst_port, protocol, ja3)
  - FileEvent (path, action, hash_before, hash_after, entropy)
  - LogEvent (event_id, source, user, description)
  - RegistryEvent (key, action, value)

Edges (relationships):
  - Process --spawned--> Process
  - Process --opened--> NetworkConnection
  - Process --modified--> FileEvent
  - Process --triggered--> LogEvent
  - Process --wrote--> RegistryEvent
  - NetworkConnection --resolved_from--> DNS query
  - FileEvent --has_hash--> ThreatIntelMatch
```

**Attack chain templates (shipped with Aegis):**

```yaml
chain: drive_by_download
  stages:
    1: browser spawns cmd/powershell/wscript
    2: interpreter creates new executable in %TEMP% or %APPDATA%
    3: new executable opens outbound connection
  mitre: [T1189, T1059, T1105]
  confidence: 95

chain: credential_theft
  stages:
    1: non-browser process reads browser credential database
    2: same process opens outbound network connection
  mitre: [T1555.003, T1041]
  confidence: 90

chain: ransomware
  stages:
    1: process modifies 50+ files in under 60 seconds
    2: modified files show entropy increase (low → high)
    OR: canary file triggered
  mitre: [T1486]
  confidence: 98

chain: persistence_installation
  stages:
    1: unsigned/new process writes to Run registry key OR Startup folder OR creates scheduled task
    2: written payload is unsigned or from temporary directory
  mitre: [T1547, T1053]
  confidence: 85

chain: fileless_attack
  stages:
    1: process spawns powershell with -enc or -encodedcommand flag
    2: powershell makes network connection
    3: no file written to disk (memory-only payload)
  mitre: [T1059.001, T1027]
  confidence: 88

chain: lateral_movement
  stages:
    1: multiple failed authentication events (4625)
    2: successful authentication (4624) with logon type 3 or 10
    3: new service or scheduled task created on target
    4: outbound connection from new service
  mitre: [T1110, T1021, T1543]
  confidence: 92

chain: data_exfiltration
  stages:
    1: process reads large number of files (documents, databases)
    2: same process opens connection to external IP
    3: significant outbound data volume (> 50MB in short window)
  mitre: [T1005, T1041]
  confidence: 80

chain: dll_injection
  stages:
    1: process calls VirtualAllocEx on another process
    2: followed by WriteProcessMemory
    3: followed by CreateRemoteThread
    OR: Sysmon event 8 (CreateRemoteThread) detected
  mitre: [T1055]
  confidence: 93
```

**Graph analysis runs continuously** (every 5 seconds), scanning the rolling 30-minute context window for pattern matches.

### 4.7 Detection Pipeline Flow

```
Event arrives from sensor
         │
    ┌────▼────┐
    │  Rule   │──── Match? ──── YES → Alert (known threat, high confidence)
    │  Engine │
    └────┬────┘
         │ NO
    ┌────▼────────────┐
    │ Isolation Forest │── Score > 0.6? ── YES ──┐
    └────┬────────────┘                          │
         │ NO (normal)                    ┌──────▼──────┐
         │                                │ Autoencoder  │
         ▼                                │ Verification │
    Log & dismiss                         └──────┬──────┘
                                                 │
                                    High error? ── YES → Alert (confirmed anomaly)
                                         │
                                         NO → Suppress (false positive)

    ┌─────────────────────────────────────────────────┐
    │  RUNNING CONTINUOUSLY IN PARALLEL:               │
    │                                                  │
    │  LSTM Sequence Analyzer                          │
    │    → Scans event sequences for temporal patterns │
    │    → Fires when suspicious sequence detected     │
    │                                                  │
    │  URL Classifier                                  │
    │    → Checks every DNS/HTTP event                 │
    │    → Fires on malicious URL classification       │
    │                                                  │
    │  Context Graph Analyzer                          │
    │    → Scans graph every 5 seconds                 │
    │    → Fires on attack chain pattern match         │
    │    → Generates full narrative with MITRE mapping │
    └─────────────────────────────────────────────────┘
```

### 4.8 Alert Scoring Formula

```
Alert Priority (0-100) = base_severity
                       × engine_confidence
                       × context_multiplier
                       × threat_intel_multiplier
                       ÷ user_familiarity_dampener

Where:
  base_severity:
    - Critical (ransomware, active exploit): 1.0
    - High (credential theft, injection): 0.8
    - Medium (suspicious behavior): 0.5
    - Low (informational anomaly): 0.2

  engine_confidence: 0.0 - 1.0 (from the detecting engine)

  context_multiplier:
    - Multiple engines agree: 1.5
    - Context graph chain match: 2.0
    - Single engine only: 1.0

  threat_intel_multiplier:
    - IOC matched in multiple feeds: 2.0
    - IOC matched in one feed: 1.5
    - No IOC match: 1.0

  user_familiarity_dampener:
    - First time seeing this pattern: 1.0
    - Seen and investigated before: 1.2
    - Dismissed 3+ times: 2.0 (significantly reduces priority)
```

---

## 5. Response Manager

### 5.1 Alert Processing Pipeline

```
Raw alert from detection engine
         │
    ┌────▼────────────┐
    │  Deduplication   │ Same alert within 60 seconds? → Merge, increment count
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  Scoring         │ Apply alert scoring formula
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  Enrichment      │ Add context: process tree, network connections,
    │                  │ threat intel results, MITRE technique info
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  Explanation     │ Generate plain-English description
    │  Generator       │ (local templates offline, Claude API if available)
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  Action          │ Generate recommended actions:
    │  Recommender     │ - "Block IP 185.x.x.x"
    │                  │ - "Kill process PID 4821"
    │                  │ - "Quarantine file C:\Users\...\malware.exe"
    │                  │ - "Disconnect network" (for critical threats)
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  Notification    │ Route to UI based on priority:
    │  Router          │ - Critical (80-100): Full-screen alert + sound
    │                  │ - High (60-79): Toast notification + tray flash
    │                  │ - Medium (30-59): Tray icon change + log entry
    │                  │ - Low (0-29): Log entry only, in daily digest
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  Forensic        │ Log everything: timestamp, sensor source,
    │  Logger          │ detection engine, raw event data, alert details,
    │                  │ user response (if any)
    └─────────────────┘
```

### 5.2 Alert Explanation Templates (Offline Mode)

When Claude API is unavailable, Aegis uses local templates:

```python
TEMPLATES = {
    "suspicious_process_chain": (
        "{parent_name} (a {parent_category} application) spawned {child_name}, "
        "which is a command interpreter. This pattern is commonly associated with "
        "{attack_type} attacks (MITRE {mitre_id}). "
        "The command line was: {cmdline_truncated}"
    ),
    "ransomware_detected": (
        "CRITICAL: {process_name} has modified {file_count} files in the last "
        "{time_window} seconds. The files show signs of encryption (entropy "
        "increased from {entropy_before:.1f} to {entropy_after:.1f}). "
        "This is consistent with ransomware behavior (MITRE T1486). "
        "Recommended: Immediately kill the process and disconnect from network."
    ),
    # ... 50+ templates covering all attack chain types
}
```

### 5.3 Available Response Actions

All actions require user approval (alert-and-recommend model):

| Action | Implementation | Reversible? |
|--------|---------------|-------------|
| Kill process | `psutil.Process(pid).kill()` | No (process terminated) |
| Block IP (outbound) | Windows Firewall rule via `netsh` | Yes (rule can be removed) |
| Block IP (inbound) | Windows Firewall rule via `netsh` | Yes |
| Quarantine file | Move to `%AEGIS_HOME%\quarantine\` with original path preserved in metadata | Yes (restore from quarantine) |
| Disconnect network | Disable network adapters via WMI | Yes (re-enable) |
| Block USB device | Disable device via WMI | Yes (re-enable) |
| Add to whitelist | Add hash/IP/process to user whitelist | Yes (remove from whitelist) |
| Dismiss alert | Mark as false positive, learn from it | Yes (un-dismiss) |

### 5.4 User Feedback Learning

```
User dismisses alert → Aegis records:
  - Alert type
  - Sensor source
  - Detection engine
  - Key attributes (process name, IP, file path, etc.)
  - User action (dismissed / investigated / acted on)

After 3 dismissals of same pattern:
  → Auto-suppress future instances
  → Add to "suppressed" section of daily digest
  → User can un-suppress at any time from dashboard

After investigation (user clicks "Investigate"):
  → Alert stays at full priority for similar future events
  → Pattern gets boosted confidence in future scoring
```

---

## 6. Desktop Application (UI)

### 6.1 Technology

- **Framework:** PySide6 (Qt for Python, LGPL licensed — compatible with open source)
- **Tray integration:** QSystemTrayIcon
- **Notifications:** Windows toast notifications via `win10toast-reborn` (for when dashboard is closed)
- **Charts:** `pyqtgraph` for real-time graphs (faster than matplotlib for live data)
- **Theming:** Dark theme by default, custom QSS stylesheet

### 6.2 System Tray

The tray icon is Aegis's always-visible presence:

```
Tray Icon States:
  🟢 Green shield — All clear, all sensors running
  🟡 Yellow shield — Warning-level alert pending review
  🔴 Red shield — Critical alert requiring immediate attention
  ⚪ Grey shield — Aegis is in learning/baseline mode

Right-click menu:
  ├── Open Dashboard
  ├── Sensor Status (submenu showing each sensor's state)
  ├── Quick Actions
  │   ├── Pause all monitoring (5 min / 15 min / 1 hour)
  │   ├── Emergency network disconnect
  │   └── Force threat intel update
  ├── Today's Summary
  ├── Settings
  └── Exit Aegis
```

### 6.3 Dashboard Window

```
┌─────────────────────────────────────────────────────────────┐
│  🛡 AEGIS                          [_][□][X]                │
├──────────┬──────────────────────────────────────────────────┤
│          │                                                   │
│ SIDEBAR  │  MAIN CONTENT AREA                               │
│          │                                                   │
│ 🏠 Home  │  (changes based on sidebar selection)            │
│          │                                                   │
│ ⚠ Alerts │                                                   │
│          │                                                   │
│ 🌐 Net   │                                                   │
│          │                                                   │
│ ⚙ Proc   │                                                   │
│          │                                                   │
│ 📁 Files │                                                   │
│          │                                                   │
│ 📊 Intel │                                                   │
│          │                                                   │
│ 🔍 Hunt  │                                                   │
│          │                                                   │
│ ⚙ Config │                                                   │
│          │                                                   │
└──────────┴──────────────────────────────────────────────────┘
```

**Home Page:**
- System health overview (all sensor statuses)
- Last 24h statistics: events processed, alerts generated, threats blocked
- Real-time activity graph (events per minute, stacked by sensor)
- Top 5 active alerts

**Alerts Page:**
- Sortable/filterable alert feed (by severity, sensor, time, status)
- Each alert shows: severity badge, timestamp, one-line summary, confidence score
- Click to expand: full explanation, context graph visualization, MITRE technique, recommended actions with one-click buttons
- Bulk actions: dismiss all low-priority, export to CSV

**Network Page:**
- Live connection table: source → destination, process, protocol, reputation score
- World map showing geographic distribution of connections (using `geoip2`)
- Top talkers (processes with most network activity)
- DNS query log with reputation indicators
- Connection reputation leaderboard (most/least trusted destinations)

**Process Page:**
- Live process tree (expandable, color-coded by risk level)
- Click any process to see: command line, DLLs, network connections, file handles, behavioral profile match
- Process DNA comparison: side-by-side of expected vs actual behavior
- Historical process timeline

**Files Page:**
- Recent file changes (filterable by directory, type, action)
- Canary file status dashboard
- Browser extension inventory
- Quarantine manager (restore or permanently delete)

**Threat Intel Page:**
- IOC database statistics (how many indicators loaded, by source)
- Recent IOC matches
- Manual lookup: enter an IP, domain, hash, or URL and get instant reputation check
- Feed health status (last update time, error status)

**Threat Hunt Page:**
- Natural language query interface: "Show me all processes that connected to IPs in Russia in the last 24 hours"
- SQL query mode for power users (direct SQLite query against event store)
- Saved queries / bookmarks

**Settings Page:**
- Sensor configuration (enable/disable each sensor, adjust sensitivity)
- Monitored directories (add/remove FIM paths)
- Trusted devices (USB whitelist)
- Trusted processes (whitelist for clipboard/screen monitoring)
- Cloud integration (enable/disable, API keys for VirusTotal/Claude/etc.)
- Alert preferences (notification sounds, suppression rules)
- Performance tuning (scan intervals, model inference frequency)
- Export/import configuration
- About / update check

---

## 7. Self-Protection Module

### 7.1 Windows Service (`aegis-service`)

A minimal Windows Service that serves as the root guardian:

```python
# Pseudocode for service behavior
class AegisService:
    """
    Minimal Windows Service that:
    1. Starts on boot (automatic startup)
    2. Launches all Aegis child processes
    3. Monitors child process health every 5 seconds
    4. Restarts any crashed child within 5 seconds
    5. Logs all crashes and restarts
    6. If the service itself is stopped, a scheduled task re-starts it
    """

    CHILD_PROCESSES = [
        'aegis-engine', 'aegis-net', 'aegis-proc', 'aegis-fim',
        'aegis-log', 'aegis-ti', 'aegis-hw', 'aegis-clip', 'aegis-detect'
    ]

    def monitor_loop(self):
        while self.running:
            for proc in self.CHILD_PROCESSES:
                if not self.is_running(proc):
                    self.log(f"CRITICAL: {proc} crashed, restarting")
                    self.restart(proc)
                    self.send_alert(f"Aegis component {proc} crashed and was restarted")
            time.sleep(5)
```

### 7.2 Self-Integrity Checks

| Check | Method | Frequency |
|-------|--------|-----------|
| Own file hashes | SHA-256 of all Aegis executables and configs | Every 60 seconds |
| Own process integrity | Verify no debugger attached, no injected DLLs | Every 30 seconds |
| Service status | Verify Windows Service is running | Every 10 seconds |
| Config file integrity | Hash of all .yaml/.json config files | Every 60 seconds |
| Scheduled task backup | Verify backup restart task exists | Every 5 minutes |

If any integrity check fails → CRITICAL alert: "Aegis self-protection triggered: [specific check] failed. Possible tampering detected."

---

## 8. Data Storage

### 8.1 SQLite Database Schema

```
aegis.db (WAL mode for concurrent read/write)
├── events          — Raw events from all sensors (rolling 30-day retention)
├── alerts          — Generated alerts with full metadata
├── baselines       — Learned normal behavior profiles per domain
├── process_dna     — Behavioral fingerprints for known processes
├── ioc_indicators  — Threat intelligence indicator database
├── connection_rep  — IP/domain reputation scores
├── user_feedback   — Alert dismissals/investigations for learning
├── device_whitelist — Approved USB devices
├── process_whitelist — Approved processes for sensitive operations
├── config          — User preferences and settings
└── audit_log       — All Aegis internal operations (self-audit trail)
```

### 8.2 Retention Policies

| Data | Retention | Reason |
|------|-----------|--------|
| Raw events | 30 days | Forensic investigation window |
| Alerts | 1 year | Historical analysis, pattern recognition |
| Baselines | Rolling 30-day window | Adaptive learning |
| Process DNA | Permanent (grows over time) | Behavioral library |
| IOC indicators | Until removed by feed update | Threat intelligence |
| Audit log | 1 year | Self-accountability |

### 8.3 Database Size Estimates

With moderate PC usage (~5000 events/hour):
- Events table: ~500MB/month (30-day retention = ~500MB)
- Alerts: ~10MB/year
- IOC database: ~200MB (millions of indicators)
- Process DNA: ~50MB (grows slowly)
- **Total: ~1GB steady state**

---

## 9. Performance Budget

### 9.1 Resource Targets

| Resource | Target | Notes |
|----------|--------|-------|
| CPU (idle) | <2% | When nothing anomalous is happening |
| CPU (active scanning) | <8% | During normal event processing |
| CPU (threat detected) | <15% | During deep analysis |
| RAM (total all processes) | <400MB | All sensors + engines + UI |
| Disk I/O | <5MB/s sustained | SQLite writes + log rotation |
| Network (Aegis itself) | <1MB/hour | Threat intel feed updates only |
| Startup time | <10 seconds | From service start to all sensors active |

### 9.2 Performance Optimizations

- **Isolation Forest inference:** <1ms per event (scikit-learn is fast for small models)
- **Autoencoder inference:** ~2ms per event (ONNX Runtime CPU)
- **LSTM inference:** ~5ms per sequence (ONNX Runtime CPU)
- **URL classifier:** <1ms per URL
- **Bloom filter IOC lookup:** <1 microsecond
- **Context graph scan:** <50ms per full scan (every 5 seconds)
- **Event bus (ZeroMQ):** <0.1ms latency per message

### 9.3 Throttling

If CPU exceeds 15% sustained:
1. Reduce scan frequency (process monitor: 5s → 10s, FIM: real-time → 5s batch)
2. Batch ML inference (queue events, process in batches of 50)
3. Reduce context graph scan frequency (5s → 15s)
4. Never disable rule engine or critical sensors

---

## 10. Installation & First Run

### 10.1 Distribution

- **Single installer:** PyInstaller bundle → NSIS installer (.exe)
- **Installs to:** `C:\Program Files\Aegis\`
- **User data:** `%APPDATA%\Aegis\` (database, configs, quarantine)
- **Registers:** Windows Service (auto-start), Start Menu shortcut, Desktop shortcut (optional)

### 10.2 First Run Wizard

```
Step 1: Welcome
  "Aegis will now learn your computer's normal behavior over the next 7 days.
   During this time, you'll see reduced alerts as the AI builds your baseline."

Step 2: Sensor Configuration
  "Which sensors would you like to enable?"
  [x] Network Monitor (recommended)
  [x] Process Watchdog (recommended)
  [x] File Integrity Monitor (recommended)
  [x] Windows Event Log Analyzer (recommended)
  [ ] USB & Hardware Monitor
  [ ] Clipboard & Screen Monitor
  [x] Threat Intelligence (recommended)

Step 3: Cloud Features (Optional)
  "Enable cloud-enhanced protection?"
  [ ] VirusTotal (requires free API key)
  [ ] AI-Powered Threat Explanations (requires Anthropic API key)
  [ ] AbuseIPDB lookups (requires free API key)
  "Aegis works fully offline without these. You can enable them later."

Step 4: Sysmon
  "Sysmon greatly enhances Aegis's detection capabilities.
   Would you like Aegis to install Sysmon for you?"
  [Install Sysmon] [Skip — I already have it] [Skip — I don't want it]

Step 5: Complete
  "Aegis is now protecting your PC. The shield icon in your system tray
   shows your current security status. Baseline learning: 0/7 days complete."
```

### 10.3 Baseline Learning Period

- Days 1-7: All sensors collect data, ML models build profiles
- Alerts are suppressed except for rule engine matches (known threats still caught)
- Progress shown in tray tooltip: "Learning: Day 3/7 (42% complete)"
- After 7 days: models are trained, full detection enabled
- User can manually extend or restart baseline at any time

---

## 11. Project Structure

```
aegis/
├── README.md
├── LICENSE (MIT)
├── pyproject.toml
├── CLAUDE.md
├── docs/
│   ├── plans/
│   │   └── 2026-02-14-aegis-design.md (this document)
│   ├── architecture.md
│   ├── user-guide.md
│   └── contributing.md
├── installer/
│   ├── aegis-installer.nsi
│   └── assets/ (icons, images)
├── src/
│   └── aegis/
│       ├── __init__.py
│       ├── __main__.py (entry point)
│       ├── core/
│       │   ├── __init__.py
│       │   ├── engine.py (Event Engine — central coordinator)
│       │   ├── bus.py (ZeroMQ message bus)
│       │   ├── context_graph.py (rolling context graph)
│       │   ├── database.py (SQLite manager)
│       │   ├── config.py (configuration manager)
│       │   └── service.py (Windows Service)
│       ├── sensors/
│       │   ├── __init__.py
│       │   ├── base.py (abstract sensor base class)
│       │   ├── network.py
│       │   ├── process.py
│       │   ├── fim.py (file integrity monitor)
│       │   ├── eventlog.py (Windows Event Log)
│       │   ├── threat_intel.py
│       │   ├── hardware.py (USB & hardware)
│       │   └── clipboard.py
│       ├── detection/
│       │   ├── __init__.py
│       │   ├── base.py (abstract detection engine base class)
│       │   ├── rule_engine.py (YARA + Sigma + behavioral rules)
│       │   ├── isolation_forest.py
│       │   ├── autoencoder.py
│       │   ├── lstm_analyzer.py
│       │   ├── url_classifier.py
│       │   ├── graph_analyzer.py (context graph pattern matching)
│       │   └── pipeline.py (detection pipeline orchestrator)
│       ├── response/
│       │   ├── __init__.py
│       │   ├── alert_manager.py (scoring, dedup, enrichment)
│       │   ├── explainer.py (plain-English generation)
│       │   ├── action_executor.py (kill, block, quarantine)
│       │   ├── feedback_learner.py (user feedback loop)
│       │   └── forensic_logger.py
│       ├── ui/
│       │   ├── __init__.py
│       │   ├── app.py (main PySide6 application)
│       │   ├── tray.py (system tray icon)
│       │   ├── dashboard.py (main window)
│       │   ├── pages/
│       │   │   ├── home.py
│       │   │   ├── alerts.py
│       │   │   ├── network.py
│       │   │   ├── processes.py
│       │   │   ├── files.py
│       │   │   ├── threat_intel.py
│       │   │   ├── threat_hunt.py
│       │   │   └── settings.py
│       │   ├── widgets/
│       │   │   ├── alert_card.py
│       │   │   ├── process_tree.py
│       │   │   ├── connection_table.py
│       │   │   ├── reputation_badge.py
│       │   │   └── real_time_chart.py
│       │   └── themes/
│       │       └── dark.qss
│       ├── models/
│       │   ├── pretrained/ (shipped baseline models)
│       │   ├── training/
│       │   │   ├── train_isolation_forest.py
│       │   │   ├── train_autoencoder.py
│       │   │   ├── train_lstm.py
│       │   │   └── train_url_classifier.py
│       │   └── inference/
│       │       └── onnx_runner.py
│       ├── rules/
│       │   ├── yara/ (YARA rule files)
│       │   ├── sigma/ (converted Sigma rules)
│       │   └── aegis/ (custom behavioral rules in YAML)
│       ├── self_protection/
│       │   ├── __init__.py
│       │   ├── integrity_checker.py
│       │   ├── process_guard.py
│       │   └── anti_tamper.py
│       └── utils/
│           ├── __init__.py
│           ├── bloom_filter.py
│           ├── hashing.py
│           ├── geoip.py
│           └── mitre_mapper.py
├── tests/
│   ├── test_sensors/
│   ├── test_detection/
│   ├── test_response/
│   ├── test_ui/
│   └── test_integration/
├── data/
│   ├── geoip/ (GeoLite2 database)
│   ├── ioc/ (pre-packaged IOC feeds)
│   └── mitre/ (ATT&CK technique database)
└── scripts/
    ├── build.py (PyInstaller build script)
    ├── install_sysmon.py
    └── download_feeds.py (initial threat intel download)
```

---

## 12. Technology Stack Summary

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.11+ | Ecosystem, ML libraries, rapid development, community |
| UI Framework | PySide6 (Qt) | Native desktop look, system tray, cross-platform potential |
| Message Bus | ZeroMQ (pyzmq) | Lightweight IPC, no server needed, sub-ms latency |
| Database | SQLite (WAL mode) | Zero config, ships with Python, handles our throughput |
| ML Training | scikit-learn, PyTorch | Industry standard, extensive model options |
| ML Inference | ONNX Runtime | Optimized CPU inference, 2-5ms per event |
| Network Capture | scapy, pyshark | Raw packet access, protocol parsing |
| Process Monitoring | psutil | Cross-platform, comprehensive process/system info |
| File Monitoring | watchdog | Real-time filesystem events |
| Windows APIs | pywin32, WMI module, pywintrace | Event logs, ETW, device management |
| Malware Signatures | yara-python | Industry standard rule matching |
| Threat Intel | requests + bloom filter | Fast IOC lookups, efficient caching |
| Charts | pyqtgraph | Real-time performance, Qt integration |
| Notifications | win10toast-reborn | Windows toast notifications |
| Installer | PyInstaller + NSIS | Single .exe installer |
| AI Explanations | Anthropic Claude API (optional) | Natural language threat explanations |

---

## 13. What Makes Aegis Better Than Existing Tools

| Capability | Windows Defender | Wazuh | Slips | Malwarebytes | **Aegis** |
|-----------|-----------------|-------|-------|--------------|-----------|
| Known threat signatures | Yes | Yes | Partial | Yes | **Yes** |
| ML anomaly detection | Limited | Limited | Yes | No | **Yes (3 engines)** |
| Context graph correlation | No | No | No | No | **Yes (killer feature)** |
| Attack chain narrative | No | Partial | No | No | **Yes with MITRE mapping** |
| Process DNA profiling | No | No | No | No | **Yes** |
| Ransomware tripwire | No | No | No | Partial | **Yes (canary files)** |
| USB attack detection | No | No | No | No | **Yes** |
| Clipboard hijack detection | No | No | No | No | **Yes** |
| Browser extension monitoring | No | No | No | No | **Yes** |
| Learning from user feedback | No | No | No | No | **Yes** |
| Plain-English explanations | No | No | No | No | **Yes** |
| Threat hunting interface | No | Yes | No | No | **Yes** |
| Single-file installer | Yes | No (complex) | No | Yes | **Yes** |
| Open source | No | Yes | Yes | No | **Yes** |
| No server required | Yes | No | Yes | Yes | **Yes** |
| Desktop app with tray | Yes | No | No | Yes | **Yes** |
| Self-protection | Yes | Partial | No | Yes | **Yes** |
| Offline-capable ML | No | No | Yes | No | **Yes** |
| Connection reputation | No | No | No | No | **Yes** |
| Adaptive baseline | No | No | Partial | No | **Yes (7-day learning)** |

**Aegis's core differentiator:** No free or affordable tool combines ML-native detection with context graph correlation in a polished desktop application. Enterprise EDRs (CrowdStrike, SentinelOne) do context correlation, but they cost $50+/endpoint/month and require cloud infrastructure. Aegis brings that capability to every PC for free.

---

## 14. Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
- Project setup (pyproject.toml, directory structure, CLAUDE.md)
- Event Engine with ZeroMQ bus
- SQLite database layer
- Configuration manager
- Basic Windows Service shell
- Basic PySide6 app with system tray icon

### Phase 2: First Sensors
- Process Watchdog (psutil-based)
- Network Sensor (scapy-based, basic flow capture)
- Wire sensors to Event Engine

### Phase 3: First Detection
- Rule Engine (YARA + basic behavioral rules)
- Isolation Forest (train on collected baseline data)
- Alert Manager (scoring, dedup, basic toast notifications)

### Phase 4: Dashboard MVP
- Home page with sensor status
- Alerts page with alert feed
- Network connections page
- Process tree page

### Phase 5: Advanced Sensors
- File Integrity Monitor with ransomware tripwire
- Windows Event Log Analyzer
- USB & Hardware Monitor
- Clipboard & Screen Monitor

### Phase 6: Advanced Detection
- Autoencoder (deep anomaly)
- LSTM Sequence Analyzer
- URL/Phishing Classifier
- Context Graph (structure + basic chain templates)

### Phase 7: Intelligence Layer
- Threat Intel Feed integration (VirusTotal, AbuseIPDB, PhishTank)
- Bloom filter IOC cache
- Connection reputation system
- Process DNA profiling
- MITRE ATT&CK mapping

### Phase 8: Polish
- Full Context Graph Analyzer with all attack chain templates
- Plain-English alert explanations (templates + optional Claude API)
- User feedback learning
- Threat hunting interface
- First-run wizard
- Self-protection module
- Performance optimization
- Installer (PyInstaller + NSIS)

---

*End of design document.*
