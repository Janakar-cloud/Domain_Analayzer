"""Tests for configuration management."""

import os
import pytest
import tempfile
from pathlib import Path

from src.core.config import Config


class TestConfig:
    """Test configuration loading and management."""

    @pytest.fixture
    def temp_config_file(self):
        """Create a temporary config file."""
        config_content = """
# Test configuration
modules:
  ct_enumeration:
    enabled: true
    timeout: 30
  dns_enumeration:
    enabled: true
    record_types:
      - A
      - AAAA
      - MX
  threat_intel:
    abuseipdb:
      enabled: true
    virustotal:
      enabled: false

rate_limits:
  crtsh: 30
  dns: 100

output:
  directory: ./test_output
  formats:
    - json
    - csv

concurrency:
  max_workers: 5
  batch_size: 25
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            yield f.name
        
        os.unlink(f.name)

    @pytest.fixture
    def temp_env_file(self):
        """Create a temporary .env file."""
        env_content = """
ABUSEIPDB_KEY=test_abuseipdb_key
OTX_KEY=test_otx_key
VT_KEY=test_vt_key
CRIMINALIP_KEY=test_criminalip_key
URLSCAN_KEY=test_urlscan_key
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            f.flush()
            yield f.name
        
        os.unlink(f.name)

    def test_config_loading(self, temp_config_file):
        """Test loading configuration from YAML."""
        config = Config(config_path=temp_config_file)
        
        assert config.get("modules.ct_enumeration.enabled") is True
        assert config.get("modules.ct_enumeration.timeout") == 30

    def test_config_nested_get(self, temp_config_file):
        """Test getting nested configuration values."""
        config = Config(config_path=temp_config_file)
        
        record_types = config.get("modules.dns_enumeration.record_types")
        assert "A" in record_types
        assert "MX" in record_types

    def test_config_default_value(self, temp_config_file):
        """Test default value for missing keys."""
        config = Config(config_path=temp_config_file)
        
        value = config.get("nonexistent.key", "default_value")
        assert value == "default_value"

    def test_config_modules_property(self, temp_config_file):
        """Test modules property."""
        config = Config(config_path=temp_config_file)
        
        modules = config.modules
        assert "ct_enumeration" in modules
        assert "dns_enumeration" in modules

    def test_config_rate_limits(self, temp_config_file):
        """Test rate limits property."""
        config = Config(config_path=temp_config_file)
        
        rate_limits = config.rate_limits
        assert rate_limits["crtsh"] == 30
        assert rate_limits["dns"] == 100

    def test_config_concurrency(self, temp_config_file):
        """Test concurrency settings."""
        config = Config(config_path=temp_config_file)
        
        concurrency = config.concurrency
        assert concurrency["max_workers"] == 5
        assert concurrency["batch_size"] == 25

    def test_config_output_formats(self, temp_config_file):
        """Test output formats."""
        config = Config(config_path=temp_config_file)
        
        formats = config.output_formats
        assert "json" in formats
        assert "csv" in formats

    def test_config_is_module_enabled(self, temp_config_file):
        """Test checking if module is enabled."""
        config = Config(config_path=temp_config_file)
        
        assert config.is_module_enabled("ct_enumeration") is True
        assert config.is_module_enabled("nonexistent_module") is False

    def test_config_get_module_config(self, temp_config_file):
        """Test getting module configuration."""
        config = Config(config_path=temp_config_file)
        
        ct_config = config.get_module_config("ct_enumeration")
        assert ct_config["enabled"] is True
        assert ct_config["timeout"] == 30

    def test_config_missing_file(self):
        """Test error when config file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            Config(config_path="/nonexistent/path/config.yaml")


class TestConfigAPIKeys:
    """Test API key management."""

    def test_api_key_loading_from_env(self, monkeypatch):
        """Test loading API keys from environment variables."""
        # Set environment variables
        monkeypatch.setenv("ABUSEIPDB_KEY", "test_key_123")
        monkeypatch.setenv("VT_KEY", "vt_test_key")
        
        # Create minimal config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("modules: {}")
            f.flush()
            config = Config(config_path=f.name)
        
        os.unlink(f.name)
        
        assert config.get_api_key("abuseipdb") == "test_key_123"
        assert config.get_api_key("virustotal") == "vt_test_key"

    def test_has_api_key(self, monkeypatch):
        """Test checking if API key exists."""
        monkeypatch.setenv("ABUSEIPDB_KEY", "test_key")
        monkeypatch.setenv("VT_KEY", "")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("modules: {}")
            f.flush()
            config = Config(config_path=f.name)
        
        os.unlink(f.name)
        
        assert config.has_api_key("abuseipdb") is True
        assert config.has_api_key("virustotal") is False
        assert config.has_api_key("nonexistent") is False

    def test_missing_api_key_returns_empty(self, monkeypatch):
        """Test missing API key returns empty string."""
        monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("modules: {}")
            f.flush()
            config = Config(config_path=f.name)
        
        os.unlink(f.name)
        
        key = config.get_api_key("abuseipdb")
        assert key == ""


class TestConfigDirectories:
    """Test directory path configuration."""

    @pytest.fixture
    def config_with_dirs(self):
        """Create config with directory settings."""
        config_content = """
output:
  directory: ./custom_output
  evidence_directory: ./custom_evidence

logging:
  file: ./custom_logs/app.log
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            f.flush()
            config = Config(config_path=f.name)
            yield config
        
        os.unlink(f.name)

    def test_output_dir_creation(self, config_with_dirs):
        """Test output directory path."""
        output_dir = config_with_dirs.output_dir
        assert isinstance(output_dir, Path)
        # Directory should be created
        assert output_dir.exists()
        
        # Cleanup
        if output_dir.exists():
            output_dir.rmdir()

    def test_evidence_dir_creation(self, config_with_dirs):
        """Test evidence directory path."""
        evidence_dir = config_with_dirs.evidence_dir
        assert isinstance(evidence_dir, Path)
        assert evidence_dir.exists()
        
        # Cleanup
        if evidence_dir.exists():
            evidence_dir.rmdir()

    def test_log_dir_creation(self, config_with_dirs):
        """Test log directory path."""
        log_dir = config_with_dirs.log_dir
        assert isinstance(log_dir, Path)
        assert log_dir.exists()
        
        # Cleanup
        if log_dir.exists():
            log_dir.rmdir()
