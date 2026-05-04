"""
app/utils/logger.py
Centralized logging configuration for SentryAgent.
"""

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.  On first call the root SentryAgent logger is
    configured with a sensible format and a StreamHandler so every module
    that calls get_logger() shares the same handler / format automatically.
    """
    root = logging.getLogger()
    
    # Configure the root logger once (idempotent — guard prevents double-add)
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        logging.getLogger("chromadb.config").setLevel(logging.WARNING)

        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("chromadb.utils.embedding_functions").setLevel(logging.WARNING)

    return logging.getLogger(name)
