import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from colorlog import ColoredFormatter

from .config import LOGS_DIR


def setup_logging(name: str, level: str = "INFO", logfile: Optional[Path] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        logger.setLevel(level.upper())
        return logger

    logger.setLevel(level.upper())
    stream_handler = logging.StreamHandler()
    stream_formatter = ColoredFormatter(
        "%(log_color)s[%(levelname)s]%(reset)s %(asctime)s - %(name)s - %(message)s",
        datefmt="%H:%M:%S",
    )
    stream_handler.setFormatter(stream_formatter)
    logger.addHandler(stream_handler)

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logfile = logfile or (LOGS_DIR / f"firewall.log")
    file_handler = RotatingFileHandler(logfile, maxBytes=2_000_000, backupCount=3)
    file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger

