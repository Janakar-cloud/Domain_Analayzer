"""Base module class for Domain Intelligence."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from ..core.config import Config
from ..core.domain import DomainResult
from ..core.logger import get_logger
from ..core.rate_limiter import RateLimiter


class BaseModule(ABC):
    """Base class for all analysis modules."""

    # Module name used in config and logging
    name: str = "base"
    
    # Description of what the module does
    description: str = "Base module"

    def __init__(
        self,
        config: Config,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        """
        Initialize module.

        Args:
            config: Configuration instance
            rate_limiter: Rate limiter instance (optional)
        """
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = get_logger(f"module.{self.name}")
        self._module_config = config.get_module_config(self.name)

    @property
    def is_enabled(self) -> bool:
        """Check if module is enabled in configuration."""
        return self._module_config.get("enabled", False)

    @property
    def timeout(self) -> int:
        """Get module timeout setting."""
        return self._module_config.get("timeout", 30)

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a module-specific setting."""
        return self._module_config.get(key, default)

    def rate_limit(self, service: Optional[str] = None) -> None:
        """
        Apply rate limiting for this module.

        Args:
            service: Service name (defaults to module name)
        """
        if self.rate_limiter:
            self.rate_limiter.wait(service or self.name)

    @abstractmethod
    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Execute the module against a domain.

        Args:
            domain: Domain name to analyze
            result: DomainResult object to populate

        This method should:
        1. Perform the analysis
        2. Add findings to result.findings
        3. Populate relevant fields in result
        4. Add any errors to result.errors
        """
        pass

    def run(self, domain: str, result: DomainResult) -> bool:
        """
        Run the module with error handling.

        Args:
            domain: Domain name to analyze
            result: DomainResult object to populate

        Returns:
            True if successful, False if errors occurred
        """
        if not self.is_enabled:
            self.logger.debug(f"Module {self.name} is disabled, skipping")
            return True

        try:
            self.logger.info(f"Running {self.name} for {domain}")
            self.execute(domain, result)
            result.modules_executed.append(self.name)
            return True
        except Exception as e:
            error_msg = f"{self.name} error: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            result.add_error(error_msg)
            return False

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(enabled={self.is_enabled})>"
