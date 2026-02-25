# -*- mode: python -*-
"""PyInstaller spec file for Aegis — AI Security Defense System.

Bundles the aegis package as a one-folder windowed application with
all required hidden imports, data files, and non-Python assets.

Usage::

    pyinstaller build/aegis.spec
    # or via the build script:
    python build/build.py
"""

from __future__ import annotations

import tomllib
from pathlib import Path

# ------------------------------------------------------------------
# Project paths
# ------------------------------------------------------------------

PROJECT_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821
SRC_DIR = PROJECT_ROOT / "src"
ENTRY_POINT = SRC_DIR / "aegis" / "__main__.py"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"

# ------------------------------------------------------------------
# Version from pyproject.toml
# ------------------------------------------------------------------

with open(PYPROJECT, "rb") as _fh:
    _proj = tomllib.load(_fh)
VERSION = _proj["project"]["version"]

# ------------------------------------------------------------------
# Hidden imports
# ------------------------------------------------------------------
# PyInstaller cannot always detect dynamic imports.  List every
# sub-module and third-party package that Aegis uses at runtime.

HIDDEN_IMPORTS: list[str] = [
    # ---- aegis sub-packages -----------------------------------
    "aegis",
    "aegis.core",
    "aegis.core.bus",
    "aegis.core.config",
    "aegis.core.coordinator",
    "aegis.core.dashboard_service",
    "aegis.core.database",
    "aegis.core.engine",
    "aegis.core.enricher",
    "aegis.core.health",
    "aegis.core.models",
    "aegis.core.scheduler",
    "aegis.core.service",
    "aegis.core.transport",
    "aegis.core.whitelist_manager",
    "aegis.core.data_bridge",
    # sensors
    "aegis.sensors",
    "aegis.sensors.base",
    "aegis.sensors.canary_system",
    "aegis.sensors.clipboard",
    "aegis.sensors.etw_providers",
    "aegis.sensors.etw_sensor",
    "aegis.sensors.eventlog",
    "aegis.sensors.file_integrity",
    "aegis.sensors.hardware",
    "aegis.sensors.health",
    "aegis.sensors.manager",
    "aegis.sensors.network",
    "aegis.sensors.process",
    "aegis.sensors.registry",
    # detection
    "aegis.detection",
    "aegis.detection.anomaly",
    "aegis.detection.autoencoder",
    "aegis.detection.beacon_detector",
    "aegis.detection.cert_analyzer",
    "aegis.detection.dns_analyzer",
    "aegis.detection.encrypted_traffic",
    "aegis.detection.fileless_detector",
    "aegis.detection.graph_analyzer",
    "aegis.detection.ja3_fingerprint",
    "aegis.detection.lolbins_analyzer",
    "aegis.detection.lstm_analyzer",
    "aegis.detection.memory_forensics",
    "aegis.detection.narratives",
    "aegis.detection.pipeline",
    "aegis.detection.powershell_analyzer",
    "aegis.detection.rule_engine",
    "aegis.detection.sigma_converter",
    "aegis.detection.url_classifier",
    "aegis.detection.win_memory",
    "aegis.detection.wmi_scanner",
    "aegis.detection.yara_scanner",
    # intelligence
    "aegis.intelligence",
    "aegis.intelligence.bloom_filter",
    "aegis.intelligence.feed_health",
    "aegis.intelligence.mitre_mapper",
    "aegis.intelligence.process_dna",
    "aegis.intelligence.reputation",
    "aegis.intelligence.stix_feed",
    "aegis.intelligence.threat_feeds",
    # alerting
    "aegis.alerting",
    "aegis.alerting.correlation_engine",
    "aegis.alerting.incident_store",
    "aegis.alerting.manager",
    # response
    "aegis.response",
    "aegis.response.action_executor",
    "aegis.response.execution_store",
    "aegis.response.explainer",
    "aegis.response.feedback_learner",
    "aegis.response.forensic_logger",
    "aegis.response.playbook_engine",
    "aegis.response.report_generator",
    "aegis.response.response_router",
    # self-protection
    "aegis.self_protection",
    "aegis.self_protection.integrity",
    "aegis.self_protection.process_guard",
    # UI
    "aegis.ui",
    "aegis.ui.app",
    "aegis.ui.dashboard",
    "aegis.ui.notifications",
    "aegis.ui.tray",
    "aegis.ui.pages",
    "aegis.ui.pages.alerts",
    "aegis.ui.pages.files",
    "aegis.ui.pages.home",
    "aegis.ui.pages.network",
    "aegis.ui.pages.processes",
    "aegis.ui.pages.settings",
    "aegis.ui.pages.threat_hunt",
    "aegis.ui.pages.threat_intel",
    "aegis.ui.themes",
    "aegis.ui.themes.dark",
    "aegis.ui.widgets",
    "aegis.ui.widgets.action_approval_dialog",
    "aegis.ui.widgets.alert_card",
    "aegis.ui.widgets.connection_table",
    "aegis.ui.widgets.fullscreen_alert",
    "aegis.ui.widgets.process_tree",
    "aegis.ui.widgets.real_time_chart",
    "aegis.ui.widgets.reputation_badge",
    # ---- third-party ------------------------------------------
    # ZeroMQ
    "zmq",
    "zmq.backend",
    "zmq.backend.cython",
    # PySide6 / Qt
    "PySide6",
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtCharts",
    "PySide6.QtSvg",
    "PySide6.QtNetwork",
    # scikit-learn
    "sklearn",
    "sklearn.ensemble",
    "sklearn.preprocessing",
    "sklearn.utils",
    # ONNX Runtime
    "onnxruntime",
    # PyTorch (optional, used by some detectors)
    "torch",
    # numpy
    "numpy",
    "numpy.core",
    # psutil
    "psutil",
    # YAML
    "yaml",
    # cryptography
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    # Windows-specific
    "ctypes",
    "ctypes.wintypes",
    "win32api",
    "win32con",
    "win32event",
    "win32service",
    "win32serviceutil",
    "servicemanager",
    "wmi",
    # scapy (network capture)
    "scapy",
    "scapy.all",
    # yara
    "yara",
    # win10toast notifications
    "win10toast",
    # Anthropic Claude API
    "anthropic",
    # Jinja2 templates
    "jinja2",
    "jinja2.ext",
    "markupsafe",
]

# ------------------------------------------------------------------
# Data files  (non-Python assets bundled into the distribution)
# ------------------------------------------------------------------

DATA_FILES: list[tuple[str, str]] = []

_data_dirs: dict[str, str] = {
    "rules": "rules",
    "data": "data",
    "tools": "tools",
}

for _src_name, _dst_name in _data_dirs.items():
    _src_path = PROJECT_ROOT / _src_name
    if _src_path.exists():
        for _file in _src_path.rglob("*"):
            if _file.is_file():
                _rel = _file.relative_to(PROJECT_ROOT)
                _dst = str(_rel.parent)
                DATA_FILES.append((str(_file), _dst))

# ------------------------------------------------------------------
# Icon  (use the .ico if it exists, otherwise skip)
# ------------------------------------------------------------------

_ico_candidate = PROJECT_ROOT / "assets" / "aegis.ico"
ICON_PATH = str(_ico_candidate) if _ico_candidate.exists() else None

# ------------------------------------------------------------------
# Windows version-info resource
# ------------------------------------------------------------------
# PyInstaller's EXE() expects *version* to be a path to a version
# info text file (or None).  We generate one dynamically so the
# embedded version always matches pyproject.toml.

_ver_parts = (VERSION.split(".") + ["0", "0", "0", "0"])[:4]
_ver_tuple = ", ".join(_ver_parts)

_VERSION_INFO_TEMPLATE = f"""\
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({_ver_tuple}),
    prodvers=({_ver_tuple}),
    mask=0x3F,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'Aegis Contributors'),
          StringStruct('FileDescription', 'Aegis AI Security Defense System'),
          StringStruct('FileVersion', '{VERSION}'),
          StringStruct('LegalCopyright', 'MIT License'),
          StringStruct('ProductName', 'Aegis'),
          StringStruct('ProductVersion', '{VERSION}'),
        ],
      ),
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ],
)
"""

_version_file = PROJECT_ROOT / "build" / "_version_info.txt"
_version_file.write_text(_VERSION_INFO_TEMPLATE, encoding="utf-8")
VERSION_FILE = str(_version_file)

# ------------------------------------------------------------------
# Analysis
# ------------------------------------------------------------------

a = Analysis(  # noqa: F821
    [str(ENTRY_POINT)],
    pathex=[str(SRC_DIR)],
    binaries=[],
    datas=DATA_FILES,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "unittest",
        "test",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="aegis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=ICON_PATH,
    version=VERSION_FILE,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="aegis",
)
