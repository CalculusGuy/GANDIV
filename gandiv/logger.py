"""
GANDIV Logging Setup
Console + persistent file logging under ~/.gandiv/logs/
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

_LOGGER_NAME = "gandiv"
_configured = False


class _ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[36m",     # cyan
        logging.INFO: "\033[32m",      # green
        logging.WARNING: "\033[33m",   # yellow
        logging.ERROR: "\033[31m",     # red
        logging.CRITICAL: "\033[41m",  # red bg
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        msg = super().format(record)
        if sys.stdout.isatty():
            return f"{color}{msg}{self.RESET}"
        return msg


def setup_logger(log_dir: Path, debug: bool = False) -> logging.Logger:
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)

    if _configured:
        return logger

    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_handler.setFormatter(_ColorFormatter("[%(asctime)s] %(levelname)-8s %(message)s", "%H:%M:%S"))
    logger.addHandler(console_handler)

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"gandiv_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s:%(lineno)d - %(message)s")
        )
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Could not open log file for writing; console-only logging active.")

    _configured = True
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
