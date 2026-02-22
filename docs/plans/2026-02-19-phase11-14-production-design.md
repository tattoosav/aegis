# Aegis — Phases 11-14: Bug Fixes & Production Readiness

**Date:** 2026-02-19
**Status:** Proposed
**Scope:** Fix critical bugs, activate sensors, wire remaining UI, harden for production

## Problem Statement

The codebase review after Phase 10 found:
- **3 critical pipeline bugs** — detection engines have interface mismatches causing silent failures (no alerts ever fire)
- **Engine not wired to UI** — dashboard receives no live data
- **Sensors never started** — `__main__.py` doesn't launch any sensor threads
- **UI integration gaps** — FullscreenAlert, NotificationManager, ActionApprovalDialog exist but aren't wired
- **Thread-unsafe SQLite** — no lock around `_conn` used from detection threads
- **Memory leak** — `_alert_history` grows without bound
- **Row selection bug** — after sorting, clicking row N selects wrong alert

## Approach: 4 Phases, Bug-Fix-First

Fix what's broken first, then activate live data, then harden.

---

## Phase 11: Critical Bug Fixes (PR #11)

**Goal:** Make the detection pipeline actually produce alerts and display them correctly.

### 11.1 Fix pipeline.py interface mismatches

**File:** `src/aegis/detection/pipeline.py`

**Bug 1 — Rule engine (line 122-126):**
```python
# BROKEN:
alert_type=f"rule_{top.name}",          # BehavioralRule has .rule_id, not .name
severity=Severity.from_string(top.severity),  # .severity is already a Severity enum
mitre_ids=[top.mitre] if hasattr(top, "mitre") and top.mitre else [],  # .mitre_ids, not .mitre

# FIX:
alert_type=f"rule_{top.rule_id}",
severity=top.severity,
mitre_ids=top.mitre_ids,
```

**Bug 2 — URL classifier (line 233-234):**
```python
# BROKEN: predict() returns tuple(str, float), code treats as dict
result = self._url_classifier.predict(url)
label = result.get("label", "benign")  # AttributeError: tuple has no .get()

# FIX:
label, confidence = self._url_classifier.predict(url)
if label == "benign":
    return None
severity = Severity.HIGH if label == "malicious" else Severity.MEDIUM
return self._make_alert(..., confidence=round(confidence, 3), ...)
```

**Bug 3 — LSTM analyzer (line 274):**
```python
# BROKEN: detect_beaconing() returns tuple(bool, dict), code treats as dict|None
result = self._lstm_analyzer.detect_beaconing([event])
if result is None: return None  # Never None — always returns tuple
return self._make_alert(..., title=result.get("description", ...))  # AttributeError

# FIX:
is_beaconing, details = self._lstm_analyzer.detect_beaconing([event])
if not is_beaconing:
    return None
return self._make_alert(
    ...,
    title=details.get("description", "Beaconing pattern detected"),
    confidence=details.get("confidence", 0.75),
    ...
)
```

**Tests:** Update `tests/test_detection/test_pipeline.py` — add 3 tests verifying each engine path produces valid Alert objects.

### 11.2 Wire engine to dashboard

**File:** `src/aegis/ui/app.py` (line 49)

```python
# BROKEN:
self._window = DashboardWindow(db=self._db)
# Engine is stored in self._engine but never passed to dashboard

# FIX:
self._window = DashboardWindow(db=self._db)
if self._engine:
    self._window.set_engine(self._engine)
```

**File:** `src/aegis/ui/dashboard.py` — add `set_engine()` method:
```python
def set_engine(self, engine) -> None:
    self._engine = engine
```

Update `_on_refresh_tick()` to also update status bar from engine:
```python
def _on_refresh_tick(self) -> None:
    if hasattr(self, '_engine') and self._engine:
        self.update_status(
            sensor_count=0,  # filled in Phase 12
            event_count=self._engine.events_processed,
            alert_count=self._engine.alerts_generated,
        )
    current = self._stack.currentWidget()
    if hasattr(current, 'refresh'):
        try:
            current.refresh()
        except Exception as exc:
            logger.debug("Page refresh failed: %s", exc)
```

### 11.3 Wire FullscreenAlert + NotificationManager

**File:** `src/aegis/__main__.py`

After creating the app, wire the notification system:
```python
from aegis.ui.notifications import NotificationManager

fullscreen_widget = FullscreenAlert(parent=app.window)
notification_manager = NotificationManager(
    tray=app.tray,
    on_fullscreen=fullscreen_widget.show_alert,
)
engine._notification_manager = notification_manager
```

**File:** `src/aegis/core/engine.py`

In `_process_alert()`, after forensic logging, notify:
```python
if self._notification_manager:
    try:
        self._notification_manager.notify(processed)
    except Exception as exc:
        logger.error("Notification failed: %s", exc)
```

### 11.4 Wire SettingsPage with config

**File:** `src/aegis/ui/dashboard.py` — `_populate_pages()`:
```python
# Pass config from __main__ through engine
config = self._engine._config if hasattr(self, '_engine') and self._engine else None
self._stack.addWidget(SettingsPage(config=config, parent=self))
```

Alternative: store config on the DashboardWindow and pass it through.

### 11.5 Fix row selection bug after table sort

**File:** `src/aegis/ui/pages/alerts.py` (line 395-401)

```python
# BROKEN: row index from table doesn't match self._alerts after sorting
def _on_row_selected(self, row: int, col: int) -> None:
    if row < 0 or row >= len(self._alerts):
        return
    alert = self._alerts[row]  # Wrong after sort!

# FIX: Store alert_id in each row using UserRole data
def _set_table_row(self, row: int, alert: Alert) -> None:
    # Add to first column's item:
    sev_item.setData(Qt.ItemDataRole.UserRole, alert.alert_id)
    ...

def _on_row_selected(self, row: int, col: int) -> None:
    item = self._table.item(row, 0)
    if item is None:
        return
    alert_id = item.data(Qt.ItemDataRole.UserRole)
    alert = next((a for a in self._alerts if a.alert_id == alert_id), None)
    if alert is None:
        return
    self._selected_alert = alert
    ...
```

### 11.6 Fix memory leak in AlertManager

**File:** `src/aegis/alerting/manager.py`

```python
MAX_HISTORY_SIZE = 10000

def process_alert(self, alert: Alert) -> Alert | None:
    with self._lock:
        ...
        self._alert_history.append(alert)
        # Evict oldest when history exceeds max
        if len(self._alert_history) > MAX_HISTORY_SIZE:
            self._alert_history = self._alert_history[-MAX_HISTORY_SIZE:]
        ...
```

Also add dedup tracker cleanup — prune entries older than 5 minutes:
```python
# In process_alert(), before dedup check:
cutoff = now - 300  # 5 minutes
expired = [k for k, (t, _) in self._dedup_tracker.items() if t < cutoff]
for k in expired:
    del self._dedup_tracker[k]
```

### 11.7 Thread-safe SQLite

**File:** `src/aegis/core/database.py`

Add a threading lock around all `_conn` access:
```python
import threading

class AegisDatabase:
    def __init__(self, path):
        self._lock = threading.Lock()
        ...

    def insert_event(self, event):
        with self._lock:
            ...
```

### Phase 11 Test Plan
- Fix + add 6 pipeline tests (rule engine, URL classifier, LSTM paths)
- Verify row selection after sort with 2 tests
- Verify alert history eviction with 1 test
- Verify dedup tracker cleanup with 1 test
- All existing 1077 tests pass

---

## Phase 12: Sensor Activation & Live Data (PR #12)

**Goal:** Start sensors so the system collects real events from the Windows PC.

### 12.1 Start sensors in __main__.py

```python
def _start_sensors(config, engine):
    """Start enabled sensors and connect to the event bus."""
    sensors = []

    # Process sensor (always enabled - core functionality)
    try:
        from aegis.sensors.process import ProcessSensor
        proc = ProcessSensor(
            interval=config.get("sensors.process.interval", 5.0),
            on_event=engine._on_event,
        )
        proc.start()
        sensors.append(proc)
        logger.info("Process sensor started")
    except Exception:
        logger.warning("Process sensor not available")

    # Network sensor
    if config.get("sensors.network.enabled", True):
        try:
            from aegis.sensors.network import NetworkSensor
            net = NetworkSensor(
                interval=config.get("sensors.network.interval", 10.0),
                on_event=engine._on_event,
            )
            net.start()
            sensors.append(net)
            logger.info("Network sensor started")
        except Exception:
            logger.warning("Network sensor not available")

    # File integrity sensor
    if config.get("sensors.fim.enabled", False):
        try:
            from aegis.sensors.file_integrity import FileIntegritySensor
            fim = FileIntegritySensor(
                interval=config.get("sensors.fim.interval", 30.0),
                on_event=engine._on_event,
            )
            fim.start()
            sensors.append(fim)
            logger.info("File integrity sensor started")
        except Exception:
            logger.warning("File integrity sensor not available")

    return sensors
```

### 12.2 Load built-in rules in __main__.py

```python
# Before creating pipeline:
rule_engine = RuleEngine()
rule_engine.load_builtin_rules()
logger.info("Loaded %d behavioral rules", rule_engine.rule_count)
pipeline_kwargs["rule_engine"] = rule_engine
```

### 12.3 Wire sensor count to status bar

Track active sensor count and update dashboard:
```python
engine._active_sensors = sensors
```

Update `_on_refresh_tick()` in dashboard:
```python
sensor_count = len(getattr(self._engine, '_active_sensors', []))
```

### 12.4 Ensure sensors gracefully handle Permission errors

Sensors may fail to read certain process info on Windows without admin.
Verify each sensor wraps `AccessDenied` exceptions gracefully.

### Phase 12 Test Plan
- Test ProcessSensor produces events (mock psutil)
- Test NetworkSensor produces events (mock psutil.net_connections)
- Test FileIntegritySensor produces events (mock fs changes)
- Test `_start_sensors()` with partial failures
- All sensors tested with `on_event` callback wiring

---

## Phase 13: UI Completion & Action Approval Flow (PR #13)

**Goal:** Complete the UI integration so every threat detection flows to the user and they can approve/decline response actions.

### 13.1 Wire ActionApprovalDialog to AlertsPage

When user clicks "Investigate" on an alert in the detail panel, show the ActionApprovalDialog with preview of recommended actions.

**File:** `src/aegis/ui/pages/alerts.py`

Add method:
```python
def set_action_executor(self, executor, forensic_logger=None):
    self._executor = executor
    self._forensic_logger = forensic_logger

def _on_investigate(self) -> None:
    if self._selected_alert is None:
        return
    self._update_selected_status(AlertStatus.INVESTIGATING)

    if hasattr(self, '_executor') and self._executor:
        from aegis.ui.widgets.action_approval_dialog import ActionApprovalDialog
        dialog = ActionApprovalDialog(parent=self)
        # Show available actions for this alert type
        for action in self._selected_alert.recommended_actions:
            preview = self._executor.preview_action(action, ...)
            dialog.show_preview(self._selected_alert.alert_id, preview)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self._executor.execute_action(preview)
```

### 13.2 Wire ProcessesPage with live data

**File:** `src/aegis/ui/pages/processes.py`

The `refresh()` method should query real process data via psutil:
```python
def refresh(self) -> None:
    if self._db:
        events = self._db.query_events(sensor="process", limit=100)
        self._populate_table(events)
```

### 13.3 Wire NetworkPage with live data

Similar to ProcessesPage — query network events from DB.

### 13.4 Add "Pause/Resume" tray menu functionality

Connect the existing tray menu items for pause/resume sensors.

### Phase 13 Test Plan
- Test ActionApprovalDialog approve/reject flow
- Test AlertsPage → ActionExecutor wiring (mock)
- Test ProcessesPage refresh with DB data
- Test NetworkPage refresh with DB data

---

## Phase 14: Production Hardening (PR #14)

**Goal:** Polish for daily use — error recovery, config persistence, logging improvements.

### 14.1 Config file persistence

Currently `AegisConfig` loads defaults. Add YAML file persistence:
- Default config at `%APPDATA%/Aegis/config.yaml`
- SettingsPage save button writes to this file
- On startup, load from file if it exists

### 14.2 Graceful error recovery

- Engine restarts sensors that crash (watchdog pattern)
- Detection pipeline continues if one engine raises
- DB connection recovery on WAL corruption

### 14.3 Logging improvements

- File-based logging to `%APPDATA%/Aegis/logs/aegis.log`
- Log rotation (10MB, keep 5 files)
- Separate debug log for detection engine output

### 14.4 First-run experience

- On first launch, show a "Getting Started" dialog
- Explain what Aegis monitors and how to approve/deny actions
- Auto-enable process + network sensors
- Start 5-minute baseline collection period

### 14.5 Cleanup service.py reference

**File:** `src/aegis/core/service.py`
Fix the import that references `aegis.sensors.process_monitor` (doesn't exist, should be `aegis.sensors.process`).

### Phase 14 Test Plan
- Test config file load/save round-trip
- Test sensor restart after crash
- Test log file creation
- Test first-run detection (no config file exists)

---

## Execution Order

| Phase | PR | Focus | Est. Files Changed |
|-------|-----|-------|-------------------|
| 11 | #11 | Critical bug fixes | ~10 |
| 12 | #12 | Sensor activation | ~5 |
| 13 | #13 | UI completion + approval flow | ~8 |
| 14 | #14 | Production hardening | ~6 |

Each phase is independently testable and deployable. Phase 11 is the highest priority — without it, **no alerts can ever fire**.

## Key Constraint

**All detected threats require explicit user approval before any response action is taken.** This is enforced by the ActionExecutor's two-phase flow: `preview_action()` → user dialog → `execute_action()`. No auto-response, ever.
