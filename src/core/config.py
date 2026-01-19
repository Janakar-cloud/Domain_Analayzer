"""Configuration management for Domain Intelligence."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv


class Config:
    """Configuration manager that loads settings from YAML and environment variables."""

    def __init__(self, config_path: Optional[str] = None, env_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to config.yaml file
            env_path: Path to .env.local file
        """
        self.base_dir = Path(__file__).parent.parent.parent
        
        # Load environment variables
        if env_path:
            load_dotenv(env_path)
        else:
            env_file = self.base_dir / ".env.local"
            if env_file.exists():
                load_dotenv(env_file)
        
        # Load YAML configuration
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = self.base_dir / "config.yaml"
        
        self._config = self._load_config()
        self._api_keys = self._load_api_keys()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment variables."""
        return {
            "abuseipdb": os.getenv("ABUSEIPDB_KEY", ""),
            "otx": os.getenv("OTX_KEY", ""),
            "virustotal": os.getenv("VT_KEY", ""),
            "criminalip": os.getenv("CRIMINALIP_KEY", ""),
            "urlscan": os.getenv("URLSCAN_KEY", ""),
        }

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.

        Args:
            key: Configuration key (e.g., 'modules.dns_enumeration.enabled')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            
            if value is None:
                return default
        
        return value

    def get_api_key(self, service: str) -> str:
        """Get API key for a service."""
        return self._api_keys.get(service, "")

    def has_api_key(self, service: str) -> bool:
        """Check if API key is configured for a service."""
        key = self._api_keys.get(service, "")
        return bool(key and key.strip())

    @property
    def modules(self) -> Dict[str, Any]:
        """Get all module configurations."""
        return self._config.get("modules", {})

    @property
    def rate_limits(self) -> Dict[str, int]:
        """Get rate limit configurations."""
        return self._config.get("rate_limits", {})

    @property
    def concurrency(self) -> Dict[str, int]:
        """Get concurrency settings."""
        return self._config.get("concurrency", {"max_workers": 10, "batch_size": 50})

    @property
    def output_dir(self) -> Path:
        """Get output directory path."""
        output_path = self._config.get("output", {}).get("directory", "./output")
        path = Path(output_path)
        if not path.is_absolute():
            path = self.base_dir / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def evidence_dir(self) -> Path:
        """Get evidence directory path."""
        evidence_path = self._config.get("output", {}).get("evidence_directory", "./evidence")
        path = Path(evidence_path)
        if not path.is_absolute():
            path = self.base_dir / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def log_dir(self) -> Path:
        """Get log directory path."""
        log_file = self._config.get("logging", {}).get("file", "./logs/domain_intel.log")
        path = Path(log_file).parent
        if not path.is_absolute():
            path = self.base_dir / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def output_formats(self) -> List[str]:
        """Get enabled output formats."""
        return self._config.get("output", {}).get("formats", ["json", "csv", "html"])

    @property
    def user_agent(self) -> str:
        """Get custom user agent string."""
        return self._config.get("user_agent", "DomainIntelligence/1.0")

    @property
    def proxy_settings(self) -> Optional[Dict[str, str]]:
        """Get proxy settings if enabled."""
        proxy_config = self._config.get("proxy", {})
        if proxy_config.get("enabled"):
            return {
                "http": proxy_config.get("http"),
                "https": proxy_config.get("https"),
            }
        return None

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled."""
        module_config = self.modules.get(module_name, {})
        return module_config.get("enabled", False)

    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """Get configuration for a specific module."""
        return self.modules.get(module_name, {})

    def reload(self) -> None:
        """Reload configuration from files."""
        self._config = self._load_config()
        self._api_keys = self._load_api_keys()
