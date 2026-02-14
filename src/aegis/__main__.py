"""Entry point for Aegis."""

import logging
import sys

from aegis import __version__


def main() -> int:
    """Launch Aegis."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("aegis")
    logger.info(f"Aegis v{__version__} starting...")

    from aegis.core.config import AegisConfig

    config = AegisConfig()
    logger.info(
        f"Config loaded. Sensors enabled: "
        f"network={config.get('sensors.network.enabled')}, "
        f"process={config.get('sensors.process.enabled')}, "
        f"fim={config.get('sensors.fim.enabled')}"
    )
    logger.info("Phase 1 foundation ready. Sensors and detection coming in Phase 2+3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
