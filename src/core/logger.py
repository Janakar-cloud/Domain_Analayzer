"""Logging setup for Domain Intelligence."""

import json
import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data

        return json.dumps(log_data)


class TextFormatter(logging.Formatter):
    """Text formatter with colors for console output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as colored text."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname

        if self.use_colors:
            color = self.COLORS.get(level, "")
            level_str = f"{color}{level:8}{self.RESET}"
        else:
            level_str = f"{level:8}"

        message = f"{timestamp} | {level_str} | {record.name} | {record.getMessage()}"

        if record.exc_info:
            message += f"\n{self.formatException(record.exc_info)}"

        return message


class DomainIntelLogger(logging.Logger):
    """Custom logger with extra data support."""

    def _log_with_data(
        self,
        level: int,
        msg: str,
        data: Optional[Dict[str, Any]] = None,
        *args,
        **kwargs
    ) -> None:
        """Log message with optional extra data."""
        if data:
            kwargs.setdefault("extra", {})["extra_data"] = data
        self.log(level, msg, *args, **kwargs)

    def info_with_data(self, msg: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """Log info message with data."""
        self._log_with_data(logging.INFO, msg, data, **kwargs)

    def debug_with_data(self, msg: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """Log debug message with data."""
        self._log_with_data(logging.DEBUG, msg, data, **kwargs)

    def warning_with_data(self, msg: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """Log warning message with data."""
        self._log_with_data(logging.WARNING, msg, data, **kwargs)

    def error_with_data(self, msg: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """Log error message with data."""
        self._log_with_data(logging.ERROR, msg, data, **kwargs)


# Register custom logger class
logging.setLoggerClass(DomainIntelLogger)

# Global logger instances
_loggers: Dict[str, DomainIntelLogger] = {}


def setup_logger(
    name: str = "domain_intel",
    level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
    max_size_mb: int = 10,
    backup_count: int = 5,
) -> DomainIntelLogger:
    """
    Set up and configure a logger.

    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Output format ('json' or 'text')
        log_file: Path to log file (optional)
        max_size_mb: Maximum log file size in MB
        backup_count: Number of backup files to keep

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler with text formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(TextFormatter(use_colors=True))
    logger.addHandler(console_handler)

    # File handler with JSON formatting (if log file specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if log_format == "json":
            file_formatter = JSONFormatter()
        else:
            file_formatter = TextFormatter(use_colors=False)

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    _loggers[name] = logger
    return logger


def get_logger(name: str = "domain_intel") -> DomainIntelLogger:
    """
    Get an existing logger or create a new one.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    if name in _loggers:
        return _loggers[name]
    
    return setup_logger(name)
