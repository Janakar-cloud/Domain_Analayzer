"""Base reporter class."""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..core.config import Config
from ..core.domain import DomainResult
from ..core.logger import get_logger


class BaseReporter(ABC):
    """Base class for all report generators."""

    # Report format identifier
    format_name: str = "base"
    
    # File extension
    extension: str = ".txt"

    def __init__(self, config: Config, output_dir: Optional[Path] = None):
        """
        Initialize reporter.

        Args:
            config: Configuration instance
            output_dir: Output directory (optional, uses config default)
        """
        self.config = config
        self.output_dir = output_dir or config.output_dir
        self.logger = get_logger(f"reporter.{self.format_name}")

    def generate_filename(self, prefix: str = "domain_intel") -> str:
        """
        Generate a timestamped filename.

        Args:
            prefix: Filename prefix

        Returns:
            Filename with timestamp
        """
        timestamp_format = self.config.get(
            "output.timestamp_format", 
            "%Y-%m-%d_%H-%M-%S"
        )
        timestamp = datetime.now().strftime(timestamp_format)
        return f"{prefix}_{timestamp}{self.extension}"

    @abstractmethod
    def generate(self, results: List[DomainResult], filename: Optional[str] = None) -> Path:
        """
        Generate report from results.

        Args:
            results: List of DomainResult objects
            filename: Optional custom filename

        Returns:
            Path to generated report
        """
        pass

    def save(self, content: str, filename: str) -> Path:
        """
        Save content to file.

        Args:
            content: Report content
            filename: Filename

        Returns:
            Path to saved file
        """
        filepath = self.output_dir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        self.logger.info(f"Report saved: {filepath}")
        return filepath
