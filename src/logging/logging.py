import logging
import sys

logger = logging.getLogger(__name__)


def configure_logging(level_str="info"):
    # Determine the log level based on the provided string
    level = logging.INFO  # Default to INFO
    if level_str.lower() == "debug":
        level = logging.DEBUG
    elif level_str.lower() == "warning":
        level = logging.WARNING
    elif level_str.lower() == "error":
        level = logging.ERROR
    elif level_str.lower() == "critical":
        level = logging.CRITICAL
    else:
        # Handle invalid level_str values
        raise ValueError(f"Invalid logging level: {level_str}")

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Set the log format
        stream=sys.stdout  # Set the stream to stdout
    )
    logger.setLevel(level)
