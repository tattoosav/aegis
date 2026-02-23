"""System coordinator for Aegis.

Replaces ad-hoc wiring in ``__main__`` with a clean lifecycle
manager that initialises all subsystems in dependency order.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from aegis.core.config import AegisConfig

logger = logging.getLogger(__name__)


class AegisCoordinator:
    """Initialises and manages the lifecycle of all Aegis components."""

    def __init__(self, config: AegisConfig) -> None:
        self._config = config
        # All components start as None
        self._db: Any = None
        self._whitelist_manager: Any = None
        self._enricher: Any = None
        self._pipeline: Any = None
        self._alert_manager: Any = None
        self._correlation_engine: Any = None
        self._incident_store: Any = None
        self._forensic_logger: Any = None
        self._playbook_engine: Any = None
        self._report_generator: Any = None
        self._engine: Any = None
        self._scheduler: Any = None
        self._canary_system: Any = None
        self._response_router: Any = None
        self._execution_store: Any = None
        self._system_health: Any = None
        self._sensors: list[Any] = []

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Initialise all components in dependency order.

        Each step is wrapped in try/except so missing optional
        dependencies never crash the system — they simply log a
        warning and leave the component as ``None``.
        """
        # 1. Database
        try:
            from aegis.core.database import AegisDatabase

            db_path = self._config.get("database.path", "aegis.db")
            db_path = str(db_path).replace(
                "%APPDATA%",
                str(Path.home() / "AppData" / "Roaming"),
            )
            self._db = AegisDatabase(db_path)
            logger.info("Database initialised: %s", db_path)
        except Exception as exc:
            logger.warning("Database init failed: %s", exc)

        # 2. WhitelistManager
        if self._config.get("whitelist.enabled", True):
            try:
                from aegis.core.whitelist_manager import (
                    WhitelistManager,
                )

                self._whitelist_manager = WhitelistManager()
                logger.info("WhitelistManager initialised")
            except Exception as exc:
                logger.warning(
                    "WhitelistManager init failed: %s", exc,
                )

        # 3. EventEnricher
        try:
            from aegis.core.enricher import EventEnricher

            self._enricher = EventEnricher(db=self._db)
            logger.info("EventEnricher initialised")
        except Exception as exc:
            logger.warning("EventEnricher init failed: %s", exc)

        # 4. Detection engines (each optional)
        pipeline_kwargs: dict[str, Any] = {}

        try:
            from aegis.detection.rule_engine import RuleEngine

            rule_engine = RuleEngine()
            rule_engine.load_builtin_rules()
            pipeline_kwargs["rule_engine"] = rule_engine
            logger.info("RuleEngine initialised")
        except Exception as exc:
            logger.warning("RuleEngine init failed: %s", exc)

        try:
            from aegis.detection.anomaly import AnomalyDetector

            pipeline_kwargs["anomaly_detector"] = AnomalyDetector()
            logger.info("AnomalyDetector initialised")
        except Exception as exc:
            logger.warning("AnomalyDetector init failed: %s", exc)

        try:
            from aegis.detection.graph_analyzer import (
                ContextGraph,
                GraphAnalyzer,
            )

            graph = ContextGraph()
            pipeline_kwargs["graph_analyzer"] = GraphAnalyzer(graph)
            logger.info("GraphAnalyzer initialised")
        except Exception as exc:
            logger.warning("GraphAnalyzer init failed: %s", exc)

        # 5. DetectionPipeline
        try:
            from aegis.detection.pipeline import DetectionPipeline

            self._pipeline = DetectionPipeline(
                whitelist_manager=self._whitelist_manager,
                **pipeline_kwargs,
            )
            logger.info("DetectionPipeline initialised")
        except Exception as exc:
            logger.warning(
                "DetectionPipeline init failed: %s", exc,
            )

        # 6. AlertManager
        try:
            from aegis.alerting.manager import AlertManager

            self._alert_manager = AlertManager()
            logger.info("AlertManager initialised")
        except Exception as exc:
            logger.warning("AlertManager init failed: %s", exc)

        # 7. CorrelationEngine + IncidentStore
        if self._config.get(
            "alerting.correlation.enabled", True,
        ):
            try:
                from aegis.alerting.correlation_engine import (
                    CorrelationEngine,
                )
                from aegis.alerting.incident_store import (
                    IncidentStore,
                )

                self._correlation_engine = CorrelationEngine(
                    time_window=self._config.get(
                        "alerting.correlation.time_window_seconds",
                        300,
                    ),
                    min_alerts_for_incident=self._config.get(
                        "alerting.correlation"
                        ".min_alerts_for_incident",
                        2,
                    ),
                )
                self._incident_store = IncidentStore(
                    self._correlation_engine, db=self._db,
                )
                logger.info(
                    "CorrelationEngine + IncidentStore initialised",
                )
            except Exception as exc:
                logger.warning(
                    "Correlation init failed: %s", exc,
                )

        # 8. ForensicLogger
        if self._db is not None:
            try:
                from aegis.response.forensic_logger import (
                    ForensicLogger,
                )

                self._forensic_logger = ForensicLogger(self._db)
                logger.info("ForensicLogger initialised")
            except Exception as exc:
                logger.warning(
                    "ForensicLogger init failed: %s", exc,
                )

        # 9. PlaybookEngine
        try:
            from aegis.response.playbook_engine import (
                PlaybookEngine,
            )

            self._playbook_engine = PlaybookEngine(
                playbooks_dir=self._config.get(
                    "response.playbooks.playbooks_dir",
                ),
            )
            self._playbook_engine.load_playbooks()
            logger.info("PlaybookEngine initialised")
        except Exception as exc:
            logger.warning(
                "PlaybookEngine init failed: %s", exc,
            )

        # 10. ReportGenerator
        try:
            from aegis.response.report_generator import (
                ReportGenerator,
            )

            self._report_generator = ReportGenerator(
                forensic_logger=self._forensic_logger,
            )
            logger.info("ReportGenerator initialised")
        except Exception as exc:
            logger.warning(
                "ReportGenerator init failed: %s", exc,
            )

        # 10b. ExecutionStore
        if self._playbook_engine is not None and self._db is not None:
            try:
                from aegis.response.execution_store import (
                    ExecutionStore,
                )

                self._execution_store = ExecutionStore(
                    self._playbook_engine, db=self._db,
                )
                logger.info("ExecutionStore initialised")
            except Exception as exc:
                logger.warning(
                    "ExecutionStore init failed: %s", exc,
                )

        # 10c. ResponseRouter
        try:
            from aegis.response.response_router import (
                ResponseRouter,
            )

            self._response_router = ResponseRouter(
                playbook_engine=self._playbook_engine,
                report_generator=self._report_generator,
                forensic_logger=self._forensic_logger,
            )
            logger.info("ResponseRouter initialised")
        except Exception as exc:
            logger.warning(
                "ResponseRouter init failed: %s", exc,
            )

        # 11. EventEngine
        try:
            from aegis.core.engine import EventEngine

            self._engine = EventEngine(
                config=self._config,
                detection_pipeline=self._pipeline,
                alert_manager=self._alert_manager,
                forensic_logger=self._forensic_logger,
            )
            if self._enricher:
                self._engine._enricher = self._enricher
            if self._correlation_engine:
                self._engine._correlation_engine = (
                    self._correlation_engine
                )
            if self._incident_store:
                self._engine._incident_store = (
                    self._incident_store
                )
            if self._playbook_engine:
                self._engine._playbook_engine = (
                    self._playbook_engine
                )
            if self._report_generator:
                self._engine._report_generator = (
                    self._report_generator
                )
            if self._response_router:
                self._engine._response_router = (
                    self._response_router
                )
            logger.info("EventEngine initialised")
        except Exception as exc:
            logger.warning("EventEngine init failed: %s", exc)

        # 12. TaskScheduler
        if self._config.get("scheduler.enabled", True):
            try:
                from aegis.core.scheduler import TaskScheduler

                self._scheduler = TaskScheduler(
                    tick_interval=self._config.get(
                        "scheduler.tick_interval_seconds", 1.0,
                    ),
                )
                self._register_scheduled_tasks()
                logger.info("TaskScheduler initialised")
            except Exception as exc:
                logger.warning(
                    "TaskScheduler init failed: %s", exc,
                )

        # 13. CanaryDeploymentSystem
        if self._config.get("canary.enabled", True):
            try:
                from aegis.sensors.canary_system import (
                    CanaryConfig,
                    CanaryDeploymentSystem,
                )

                canary_cfg = CanaryConfig(
                    directories=[
                        Path(d)
                        for d in self._config.get(
                            "canary.directories", [],
                        )
                    ],
                    file_types=self._config.get(
                        "canary.file_types",
                        [".txt", ".docx"],
                    ),
                    files_per_directory=self._config.get(
                        "canary.files_per_directory", 2,
                    ),
                    verification_interval_seconds=self._config.get(
                        "canary.verification_interval_seconds",
                        60,
                    ),
                )
                self._canary_system = CanaryDeploymentSystem(
                    canary_cfg,
                )
                logger.info("CanaryDeploymentSystem initialised")
            except Exception as exc:
                logger.warning(
                    "CanaryDeploymentSystem init failed: %s", exc,
                )

        # 14. SystemHealth
        try:
            from aegis.core.health import SystemHealth

            self._system_health = SystemHealth(self)
            logger.info("SystemHealth initialised")
        except Exception as exc:
            logger.warning("SystemHealth init failed: %s", exc)

    # ------------------------------------------------------------------
    # Scheduled tasks
    # ------------------------------------------------------------------

    def _register_scheduled_tasks(self) -> None:
        """Register built-in periodic tasks with the scheduler."""
        if self._scheduler is None:
            return

        # Retention cleanup — once per day
        if self._db is not None:
            retention_days = self._config.get(
                "database.retention_days", 90,
            )

            def _retention_cleanup() -> None:
                self._db.purge_old_events(retention_days)
                self._db.purge_old_alerts(retention_days)

            self._scheduler.add_task(
                name="retention_cleanup",
                callback=_retention_cleanup,
                interval_seconds=86_400,
            )

        # Canary verification
        if self._canary_system is not None:
            interval = self._config.get(
                "canary.verification_interval_seconds", 60,
            )

            def _canary_verify() -> None:
                triggered = self._canary_system.verify_all()
                if triggered and self._engine is not None:
                    events = self._canary_system.to_events(
                        triggered,
                    )
                    for ev in events:
                        self._engine._on_event(ev)

            self._scheduler.add_task(
                name="canary_verify",
                callback=_canary_verify,
                interval_seconds=interval,
            )

        # Whitelist pruning — once per hour
        if self._whitelist_manager is not None:
            self._scheduler.add_task(
                name="whitelist_prune",
                callback=self._whitelist_manager.prune_expired,
                interval_seconds=3_600,
            )

        # Stale incident pruning — once per hour
        if self._correlation_engine is not None:
            max_age = (
                self._config.get(
                    "alerting.correlation.time_window_seconds",
                    300,
                )
                * 2
            )

            def _stale_incident_prune() -> None:
                self._correlation_engine.prune_stale_incidents(
                    max_age,
                )

            self._scheduler.add_task(
                name="stale_incident_prune",
                callback=_stale_incident_prune,
                interval_seconds=3_600,
            )

        # Execution store sync — every 5 minutes
        if self._execution_store is not None:
            self._scheduler.add_task(
                name="execution_store_sync",
                callback=self._execution_store.sync_from_engine,
                interval_seconds=300,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start all components in dependency order."""
        if self._engine is not None:
            self._engine.start()

        if (
            self._config.get("canary.enabled", True)
            and self._canary_system is not None
        ):
            try:
                self._canary_system.deploy_all()
                logger.info("Canary files deployed")
            except Exception as exc:
                logger.warning(
                    "Canary deployment failed: %s", exc,
                )

        if self._scheduler is not None:
            self._scheduler.start()

        logger.info("AegisCoordinator started")

    def stop(self) -> None:
        """Stop all components in reverse dependency order."""
        if self._scheduler is not None:
            self._scheduler.stop()

        for sensor in self._sensors:
            try:
                sensor.stop()
            except Exception as exc:
                logger.warning(
                    "Sensor stop failed: %s", exc,
                )

        if self._canary_system is not None:
            try:
                self._canary_system.cleanup()
            except Exception as exc:
                logger.warning(
                    "Canary cleanup failed: %s", exc,
                )

        if self._engine is not None:
            self._engine.stop()

        logger.info("AegisCoordinator stopped")

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def engine(self) -> Any:
        """The central :class:`EventEngine`, or ``None``."""
        return self._engine

    @property
    def db(self) -> Any:
        """The :class:`AegisDatabase`, or ``None``."""
        return self._db

    @property
    def scheduler(self) -> Any:
        """The :class:`TaskScheduler`, or ``None``."""
        return self._scheduler

    @property
    def whitelist_manager(self) -> Any:
        """The :class:`WhitelistManager`, or ``None``."""
        return self._whitelist_manager

    @property
    def correlation_engine(self) -> Any:
        """The :class:`CorrelationEngine`, or ``None``."""
        return self._correlation_engine

    @property
    def canary_system(self) -> Any:
        """The :class:`CanaryDeploymentSystem`, or ``None``."""
        return self._canary_system

    @property
    def incident_store(self) -> Any:
        """The :class:`IncidentStore`, or ``None``."""
        return self._incident_store

    @property
    def enricher(self) -> Any:
        """The :class:`EventEnricher`, or ``None``."""
        return self._enricher

    @property
    def response_router(self) -> Any:
        """The :class:`ResponseRouter`, or ``None``."""
        return self._response_router

    @property
    def execution_store(self) -> Any:
        """The :class:`ExecutionStore`, or ``None``."""
        return self._execution_store

    @property
    def system_health(self) -> Any:
        """The :class:`SystemHealth`, or ``None``."""
        return self._system_health

    @property
    def playbook_engine(self) -> Any:
        """The :class:`PlaybookEngine`, or ``None``."""
        return self._playbook_engine

    @property
    def report_generator(self) -> Any:
        """The :class:`ReportGenerator`, or ``None``."""
        return self._report_generator

    @property
    def forensic_logger(self) -> Any:
        """The :class:`ForensicLogger`, or ``None``."""
        return self._forensic_logger
