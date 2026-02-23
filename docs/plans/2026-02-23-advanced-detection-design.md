# Advanced Detection Layer — Design Document

**Date:** 2026-02-23
**Status:** Approved
**Phase:** 24+ (Advanced Detection Superpowers)

## Overview

Add three advanced detection capabilities to Aegis: memory forensics, encrypted traffic analysis, and fileless attack detection. These are implemented as enhanced sensors + new detection engines plugged into the existing pipeline, powered by a unified ETW (Event Tracing for Windows) sensor.

### Goals

- Detect in-memory-only malware (reflective DLL injection, process hollowing, shellcode)
- Identify C2 beaconing over encrypted channels without decryption
- Catch fileless attacks (PowerShell obfuscation, WMI persistence, LOLBins, .NET memory loads)
- Maximize detection rate; use existing feedback learner to tune false positives over time
- Full depth: ETW for real-time kernel visibility + optional kernel minifilter driver

### Architecture

```
ETW Sensor ──► Event Bus ──► MemoryForensicsEngine
                           ──► FilelessAttackEngine
                           ──► EncryptedTrafficEngine

Process Sensor (enhanced: memory region scanning, DLL path validation)
Network Sensor (enhanced: Scapy TLS capture, JA3/JA4, certificate extraction)
```

All three engines register with the existing `DetectionPipeline` and run in parallel alongside rule engine, anomaly detector, autoencoder, LSTM, etc. Findings flow through existing alert scoring, deduplication, and correlation.

---

## 1. ETW Sensor

**File:** `src/aegis/sensors/etw_sensor.py`

Creates a single real-time ETW tracing session subscribed to 7 providers:

| Provider | GUID | Keywords | Purpose |
|----------|------|----------|---------|
| Microsoft-Windows-Kernel-Process | `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | 0x10 (ImageLoad) | Process/thread creation, DLL loads |
| Microsoft-Windows-DotNETRuntime | `{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}` | 0x1C (Loader+JIT+AssemblyLoader) | Assembly loads, JIT compilation |
| Microsoft-Windows-PowerShell | `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}` | 0xFFFF | Script block logging |
| Microsoft-Windows-AMSI | `{2A576B87-09A7-520E-C21A-4942F0271D67}` | all | AMSI scan results, bypass detection |
| Microsoft-Windows-WMI-Activity | `{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}` | all | WMI persistence, remote execution |
| Microsoft-Windows-WinINet | `{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}` | all | HTTP URLs/headers from Windows TLS stack |
| Microsoft-Windows-Schannel | `{1F678132-5938-4686-9FDC-C8FF68F15C85}` | all | TLS handshake details, cipher negotiation |

### Implementation

- Uses `pywintrace` (Mandiant's ctypes ETW wrapper) or custom ctypes wrapper if compatibility issues arise with Python 3.11+
- Dedicated thread for `ProcessTrace` (blocking ETW consumer loop)
- Events parsed into typed dataclasses and published to ZeroMQ event bus
- Requires admin privileges (standard for ETW consumption)
- Graceful degradation if a provider is unavailable (log warning, skip provider)

### Event Types Emitted

| Event | Fields | Consumers |
|-------|--------|-----------|
| `etw.process_image_load` | pid, image_path, image_base, image_size | MemoryForensics, Fileless |
| `etw.dotnet_assembly_load` | pid, assembly_name, module_il_path, is_dynamic | Fileless |
| `etw.powershell_scriptblock` | pid, script_text, script_block_id, path | Fileless |
| `etw.amsi_scan` | pid, content_name, result, app_name | Fileless |
| `etw.wmi_activity` | pid, operation, namespace, query | Fileless |
| `etw.http_request` | pid, url, method, headers | EncryptedTraffic |
| `etw.tls_handshake` | pid, server_name, cipher_suite, tls_version | EncryptedTraffic |

---

## 2. Memory Forensics Engine

**File:** `src/aegis/detection/memory_forensics.py`

Scans process memory for injection artifacts using techniques from PE-sieve and Moneta.

### Detection Capabilities

| Technique | MITRE | Detection Method |
|-----------|-------|-----------------|
| Reflective DLL injection | T1620 | Scan private executable memory for PE headers (MZ) not in PEB module list |
| Process hollowing | T1055.012 | Compare in-memory PE sections against on-disk file via `pefile` |
| Shellcode injection | T1055 | High-entropy executable private regions without PE headers |
| RWX memory regions | T1055 | Flag PAGE_EXECUTE_READWRITE private regions |
| .NET assembly injection | T1620 | PE in private memory with .NET metadata signature (BSJB) |
| CLR in non-.NET processes | T1059.001 | Flag clr.dll/coreclr.dll load in notepad, rundll32, etc. |
| Inline hook detection | T1056.004 | Compare first bytes of exports in ntdll/kernel32/kernelbase against on-disk originals |
| Thread start address validation | T1055.003 | Enumerate threads, flag start addresses in private/unbacked memory |

### Implementation

- `ctypes` + Windows API: `VirtualQueryEx`, `ReadProcessMemory`, `EnumProcessModulesEx`, `CreateToolhelp32Snapshot`
- Read-only access: `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
- Skip critical processes: csrss, lsass, smss, wininit, services, svchost, System
- Throttled scanning: max 50 MB/s memory reads, yields between regions
- Entropy via Shannon formula (threshold: >4.0 for code, >6.0 encrypted/compressed)
- YARA scanning of suspicious regions (integrates with existing `yara_scanner.py`)

### Scanning Modes

1. **Event-triggered**: ETW reports suspicious image load → scan that process immediately
2. **Periodic sweep**: Every 60s, scan processes with network connections or high privilege
3. **On-demand**: User-initiated from dashboard

### Hook Detection Details

Focus on security-critical DLLs: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `advapi32.dll`, `ws2_32.dll`. For each exported function:
1. Read first 16 bytes from memory
2. Read first 16 bytes from on-disk file at same RVA (adjusted for ASLR rebasing)
3. If bytes differ and memory starts with JMP/CALL opcode, flag as hooked
4. Record hook destination address and whether it falls in a known module

### Thread Scanning Details

1. `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` to enumerate all threads
2. `OpenThread` + `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` to get start address
3. Cross-reference against loaded module ranges
4. Threads starting outside any loaded module = suspicious (T1055.003)

---

## 3. Encrypted Traffic Analysis Engine

**File:** `src/aegis/detection/encrypted_traffic.py`

Analyzes encrypted network traffic for C2 indicators without decryption.

### Detection Capabilities

| Technique | MITRE | Detection Method |
|-----------|-------|-----------------|
| JA3/JA4 fingerprinting | T1573 | Compute JA3 hash from TLS ClientHello, check SSLBL blacklist |
| Certificate anomaly detection | T1573.002 | Parse certs: self-signed, short-lived, missing SAN, weak keys, CS defaults |
| Beacon timing analysis | T1071.001 | Inter-arrival time stats: CV, tolerance %, median interval |
| FFT periodicity detection | T1071.001 | Fast Fourier Transform on connection timestamps for hidden periodicity |
| DoH detection | T1568 | Non-browser processes to known DoH IPs + flow-based ML |
| ETW HTTP monitoring | T1071.001 | WinINet/WebIO ETW events capture URLs from Windows TLS stack |
| JARM active scanning | T1573 | 10 crafted TLS ClientHellos → hash server response → compare C2 database |
| Flow ML classifier | T1573 | Random Forest on flow features: packet sizes, timing, volume ratios |

### JA3/JA4 Implementation

- Scapy `TLSClientHello` parsing with `TCPSession` for TCP reassembly
- Extract: TLS version, cipher suites, extensions, elliptic curves, EC point formats
- MD5 hash → JA3 fingerprint
- JA4: sort extensions before hashing, structured prefix with ALPN
- Requires Npcap on Windows for live capture

### Certificate Analysis

Uses `cryptography` library for X.509 parsing:
- Self-signed: issuer == subject
- Short-lived: validity < 30 days
- Missing SAN extension
- Weak key: RSA < 2048 bits
- Known C2 patterns: Cobalt Strike default cert fields

### Beacon Detection

**Statistical approach:**
- Track per-destination connection timestamps
- Compute inter-arrival deltas
- Metrics: median delta, std deviation, coefficient of variation (CV)
- Beacon score: CV < 0.2 (+0.4), 70%+ within tolerance (+0.3), in beacon range 20-3600s (+0.2), sustained pattern (+0.1)
- Threshold: score >= 0.7 → beacon alert

**FFT approach:**
- Bin timestamps into 1-second intervals
- Remove DC component (mean)
- FFT to find dominant frequency
- Signal-to-noise ratio > 5.0 → periodic beaconing
- Catches up to 50% jitter (Cobalt Strike maximum)

### JARM Active Scanning

- Only triggered on already-suspicious connections (suspicious JA3, anomalous timing, unknown cert)
- Send 10 crafted TLS ClientHellos with varying parameters
- Hash concatenated server responses (SHA256, truncated)
- Compare against known C2 JARM hashes:
  - Cobalt Strike: `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`
  - Metasploit: `07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2`

### Flow ML Classifier

Features (per flow):
```
fwd_pkt_size_{mean,std,min,max}
bwd_pkt_size_{mean,std,min,max}
flow_duration_sec
fwd_iat_{mean,std}, bwd_iat_{mean,std}
total_{fwd,bwd}_packets, total_{fwd,bwd}_bytes
bytes_per_second, packets_per_second
cipher_suite_count, extension_count
ja3_is_known_malicious
fwd_bwd_packet_ratio, fwd_bwd_byte_ratio
```

Algorithm: Random Forest (primary) + XGBoost (ensemble). Integrates with existing `AnomalyDetector` infrastructure. Pre-trained model with option for environment-specific fine-tuning.

### Threat Intelligence: SSLBL Feed

New feed class `SSLBLFeed` in `intelligence/threat_feeds.py`:
- Source: `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv`
- Update interval: 5 minutes
- Fields: JA3 hash, malware family, listing reason
- Indexed in existing Bloom filter for O(1) lookups

---

## 4. Fileless Attack Detection Engine

**File:** `src/aegis/detection/fileless_detector.py`

Detects attacks operating entirely in memory without disk artifacts.

### Detection Capabilities

| Technique | MITRE | Detection Method |
|-----------|-------|-----------------|
| PowerShell obfuscation | T1027 | Shannon entropy (>5.0), regex bank for 8+ obfuscation categories |
| AMSI integration | T1059.001 | ctypes wrapper around amsi.dll, scan suspicious script blocks |
| AMSI bypass detection | T1562.001 | Monitor AMSI ETW for scan cessation, cross-ref memory forensics |
| WMI persistence | T1546.003 | Enumerate all WMI namespaces for dangerous event consumers |
| LOLBins analysis | T1218 | Parent-child analysis (40+ pairs), command-line pattern matching |
| .NET fileless | T1620 | CLR ETW: empty ModuleILPath, CLR loads in non-.NET processes |

### PowerShell Obfuscation Detection

**Entropy analysis:**
- Shannon entropy on script block text
- Clean PowerShell: 3.5 - 4.7
- Base64-encoded: 5.5 - 6.0
- XOR/custom-encoded: 6.0+
- Threshold: >5.0 triggers further analysis

**Pattern bank** (regex-based):
1. `base64_encodedcommand` — `-enc` parameter with base64 payload
2. `base64_inline` — `[Convert]::FromBase64String`
3. `backtick_obfuscation` — `I`nv`oke-`Exp`ression` pattern
4. `string_concat` — `'Inv'+'oke'+'-Exp'+'ression'`
5. `char_array_join` — `[char[]]@(73,110,118) -join ''`
6. `replace_deobfuscation` — string replacement to reconstruct commands
7. `format_string` — `'{2}{0}{1}' -f 'ke-Ex','pression','Invo'`
8. `compressed_stream` — DeflateStream/GZipStream payloads

### AMSI Integration

ctypes wrapper around `amsi.dll`:
- `AmsiInitialize` → context
- `AmsiOpenSession` → session
- `AmsiScanBuffer` → result (CLEAN / NOT_DETECTED / BLOCKED / DETECTED)
- Scan suspicious script blocks before alerting (reduces false positives)
- AMSI bypass detection: monitor ETW for sudden cessation of scan events after initial activity

### WMI Persistence Detection

**Periodic scan** (every 5 minutes):
1. Recursively enumerate all WMI namespaces starting from `root`
2. For each namespace, query for `CommandLineEventConsumer` and `ActiveScriptEventConsumer`
3. Query for `__FilterToConsumerBinding` to find active persistence
4. Any binding = alert (legitimate WMI subscriptions are rare)

**Real-time** via WMI-Activity ETW:
- Event IDs 5857-5861: provider load, query execution, method calls
- Flag remote WMI operations (lateral movement indicator)

### LOLBins Database

Stored as YAML in `rules/lolbins/`:

```yaml
# rules/lolbins/certutil.yaml
binary: certutil.exe
mitre: T1218
suspicious_parents:
  - cmd.exe  # when cmd.exe was spawned by Office
  - powershell.exe
suspicious_args:
  - pattern: "-urlcache"
    severity: high
    description: "File download via certutil"
  - pattern: "-decode"
    severity: medium
    description: "Base64 decode via certutil"
network_expected: false  # certutil shouldn't make connections normally
```

**Parent-child analysis:**
- 40+ suspicious pairs maintained in the YAML database
- Key pairs: Office apps → shells, wmiprvse → anything, svchost → unusual children
- Scoring: exact parent-child match = high, partial match = medium

### .NET Fileless Detection

Consumes `etw.dotnet_assembly_load` events:
- `ModuleILPath` empty or name-only (no disk path) = memory-only assembly → CRITICAL
- `IsLoaded` in non-.NET process (notepad, rundll32, certutil, etc.) → HIGH
- JIT compilation burst (>20 methods JIT'd in <1 second from unknown assembly) → HIGH

---

## 5. Sensor Enhancements

### Enhanced Process Sensor

**File:** `src/aegis/sensors/process.py` (modifications)

New capabilities:
- Memory region metadata via `VirtualQueryEx` for processes with network activity
- DLL load path validation: flag DLLs from `%TEMP%`, `%APPDATA%`, user Downloads
- Parent-child relationship tracking with full command-line
- Emit `process.memory_anomaly` on RWX regions or unbacked executable memory

### Enhanced Network Sensor

**File:** `src/aegis/sensors/network.py` (modifications)

New capabilities:
- Scapy-based TLS ClientHello capture (requires Npcap)
- JA3/JA4 fingerprint computation in real-time
- Server certificate extraction from TLS handshake
- Per-destination connection timestamp tracking for beacon analysis
- Graceful fallback to psutil-only if Npcap unavailable

---

## 6. Kernel Minifilter Driver (Optional)

**Directory:** `src/aegis/drivers/aegis_minifilter/` (C project, WDK)

Optional kernel-level driver for maximum visibility. Aegis works fully without it.

### What It Provides Beyond ETW

| Capability | Benefit |
|-----------|---------|
| File I/O interception | See every file operation, including by rootkits |
| Pre-operation callbacks | Block operations before completion (e.g., ransomware prevention) |
| Registry filtering | Kernel-level registry modification interception |
| Process/thread callbacks | PsSetCreateProcessNotifyRoutineEx — unevadable process notification |
| Object manager callbacks | ObRegisterCallbacks — detect LSASS access (T1003.001 Mimikatz) |
| ETW TI relay | PPL driver can consume Microsoft-Windows-Threat-Intelligence events |

### Architecture

```
Kernel Mode: aegis_minifilter.sys
  ├── FltRegisterFilter (file operations)
  ├── CmRegisterCallbackEx (registry operations)
  ├── PsSetCreateProcessNotifyRoutineEx (process creation)
  ├── ObRegisterCallbacks (handle operations — LSASS protection)
  └── EtwRegister (TI ETW consumer, requires PPL)
       │
       ▼ FilterCommunicationPort
User Mode: aegis_driver_bridge.py
  ├── FilterConnectCommunicationPort (ctypes)
  ├── Event deserialization
  └── Publish to ZeroMQ event bus
```

### LSASS Protection (T1003.001)

ObRegisterCallbacks detects any process opening a handle to lsass.exe with PROCESS_VM_READ:
- Catches Mimikatz, comsvcs.dll MiniDump, procdump, and custom dumpers
- Can deny the handle request (blocking mode) or alert-only (monitoring mode)

### Deployment Phases

1. **Phase 1 (no driver):** ETW-only — works out of the box, no signing needed
2. **Phase 2 (basic driver):** File/registry/process callbacks with EV code signing certificate
3. **Phase 3 (PPL driver):** Microsoft ELAM program enrollment for TI ETW access

### Requirements

- Written in C using Windows Driver Kit (WDK)
- EV code signing certificate for kernel driver (Windows 10+)
- ELAM enrollment for PPL (long-term, Phase 3)
- Installed via NSIS installer or `fltmc load`

---

## 7. New Dependencies

| Package | Purpose | Required? |
|---------|---------|-----------|
| `pywintrace` | ETW consumption | Yes (or custom ctypes) |
| `pefile` | PE parsing for hollowing detection | Yes |
| `cryptography` | X.509 certificate analysis | Yes |
| `scapy` | TLS ClientHello capture | Already in project |
| Npcap | Windows packet capture driver | Optional (graceful degradation) |
| WDK | Kernel driver development | Optional (minifilter only) |

---

## 8. MITRE ATT&CK Coverage Added

| ID | Technique | Engine |
|----|-----------|--------|
| T1003.001 | OS Credential Dumping: LSASS Memory | Minifilter (ObRegisterCallbacks) |
| T1027 | Obfuscated Files or Information | Fileless |
| T1047 | Windows Management Instrumentation | Fileless |
| T1055 | Process Injection (generic) | Memory Forensics |
| T1055.001 | Dynamic-link Library Injection | Memory Forensics |
| T1055.003 | Thread Execution Hijacking | Memory Forensics |
| T1055.012 | Process Hollowing | Memory Forensics |
| T1056.004 | Credential API Hooking | Memory Forensics |
| T1059.001 | PowerShell | Fileless |
| T1071.001 | Application Layer Protocol: Web | Encrypted Traffic |
| T1218 | System Binary Proxy Execution | Fileless |
| T1546.003 | Event Triggered Execution: WMI | Fileless |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Fileless (AMSI bypass) |
| T1568 | Dynamic Resolution | Encrypted Traffic (DoH) |
| T1573 | Encrypted Channel | Encrypted Traffic |
| T1573.002 | Encrypted Channel: Asymmetric Crypto | Encrypted Traffic (cert anomaly) |
| T1620 | Reflective Code Loading | Memory Forensics |

---

## 9. Testing Strategy

Each new component follows TDD (test-first):

- **ETW Sensor:** Mock ETW events, verify parsing and bus publication
- **Memory Forensics:** Mock VirtualQueryEx/ReadProcessMemory returns, inject known patterns
- **Encrypted Traffic:** Synthetic JA3 computation, mock SSLBL responses, generated beacon timestamps
- **Fileless Detector:** Sample obfuscated scripts, mock WMI returns, LOLBin command-line examples
- **Integration tests:** End-to-end event flow from ETW mock through detection pipeline to alert

Target: 200+ new tests across the four new components.
