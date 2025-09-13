#!/usr/bin/env python3
"""
Amoskys Configuration Management

This module provides centralized configuration for the entire Amoskys system.
It loads configuration from environment variables, YAML files, and provides validation.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class EventBusConfig:
    """EventBus server configuration"""
    host: str = "0.0.0.0"
    port: int = 50051
    tls_enabled: bool = True
    cert_dir: str = "certs"
    overload_mode: bool = False
    max_inflight: int = 100
    hard_max: int = 500
    metrics_port_1: int = 9000
    metrics_port_2: int = 9100
    health_port: int = 8080
    metrics_disabled: bool = False
    log_level: str = "INFO"


@dataclass
class AgentConfig:
    """Agent configuration"""
    cert_dir: str = "certs"
    wal_path: str = "data/wal/flowagent.db"
    bus_address: str = "localhost:50051"
    max_env_bytes: int = 131072  # 128KB
    send_rate: int = 0  # 0=unlimited
    retry_max: int = 6
    retry_timeout: float = 1.0
    metrics_port: int = 9101
    health_port: int = 8081
    log_level: str = "INFO"


@dataclass
class CryptoConfig:
    """Cryptography configuration"""
    ed25519_private_key: str = "certs/agent.ed25519"
    trust_map_path: str = "config/trust_map.yaml"
    ca_cert: str = "certs/ca.crt"
    server_cert: str = "certs/server.crt"
    server_key: str = "certs/server.key"
    agent_cert: str = "certs/agent.crt"
    agent_key: str = "certs/agent.key"


@dataclass
class StorageConfig:
    """Storage configuration"""
    data_dir: str = "data"
    wal_dir: str = "data/wal"
    storage_dir: str = "data/storage"
    metrics_dir: str = "data/metrics"
    max_wal_bytes: int = 200 * 1024 * 1024  # 200MB


@dataclass
class AmoskysConfig:
    """Main configuration container"""
    eventbus: EventBusConfig = field(default_factory=EventBusConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    
    @classmethod
    def from_env(cls) -> 'AmoskysConfig':
        """Load configuration from environment variables"""
        config = cls()
        
        # EventBus configuration
        config.eventbus.host = os.getenv("BUS_HOST", config.eventbus.host)
        config.eventbus.port = int(os.getenv("BUS_SERVER_PORT", str(config.eventbus.port)))
        config.eventbus.overload_mode = os.getenv("BUS_OVERLOAD", "false").lower() in ("1", "true", "on", "yes")
        config.eventbus.max_inflight = int(os.getenv("BUS_MAX_INFLIGHT", str(config.eventbus.max_inflight)))
        config.eventbus.hard_max = int(os.getenv("BUS_HARD_MAX", str(config.eventbus.hard_max)))
        config.eventbus.metrics_port_1 = int(os.getenv("BUS_METRICS_PORT_1", str(config.eventbus.metrics_port_1)))
        config.eventbus.metrics_port_2 = int(os.getenv("BUS_METRICS_PORT_2", str(config.eventbus.metrics_port_2)))
        config.eventbus.health_port = int(os.getenv("BUS_HEALTH_PORT", str(config.eventbus.health_port)))
        config.eventbus.metrics_disabled = os.getenv("BUS_METRICS_DISABLE", "") in ("1", "true", "on", "yes")
        config.eventbus.log_level = os.getenv("LOGLEVEL", config.eventbus.log_level).upper()
        
        # Agent configuration
        config.agent.cert_dir = os.getenv("IS_CERT_DIR", config.agent.cert_dir)
        config.agent.wal_path = os.getenv("IS_WAL_PATH", config.agent.wal_path)
        config.agent.bus_address = os.getenv("IS_BUS_ADDRESS", config.agent.bus_address)
        config.agent.max_env_bytes = int(os.getenv("IS_MAX_ENV_BYTES", str(config.agent.max_env_bytes)))
        config.agent.send_rate = int(os.getenv("IS_SEND_RATE", str(config.agent.send_rate)))
        config.agent.retry_max = int(os.getenv("IS_RETRY_MAX", str(config.agent.retry_max)))
        config.agent.retry_timeout = float(os.getenv("IS_RETRY_TIMEOUT", str(config.agent.retry_timeout)))
        config.agent.metrics_port = int(os.getenv("IS_METRICS_PORT", str(config.agent.metrics_port)))
        config.agent.health_port = int(os.getenv("IS_HEALTH_PORT", str(config.agent.health_port)))
        config.agent.log_level = os.getenv("LOGLEVEL", config.agent.log_level).upper()
        
        # Storage configuration
        config.storage.data_dir = os.getenv("IS_DATA_DIR", config.storage.data_dir)
        config.storage.wal_dir = os.getenv("IS_WAL_DIR", config.storage.wal_dir)
        config.storage.storage_dir = os.getenv("IS_STORAGE_DIR", config.storage.storage_dir)
        config.storage.max_wal_bytes = int(os.getenv("IS_MAX_WAL_BYTES", str(config.storage.max_wal_bytes)))
        
        return config
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'AmoskysConfig':
        """Load configuration from YAML file"""
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        config = cls()
        
        # Update configuration from YAML
        if 'eventbus' in data:
            for key, value in data['eventbus'].items():
                if hasattr(config.eventbus, key):
                    setattr(config.eventbus, key, value)
        
        if 'agent' in data:
            for key, value in data['agent'].items():
                if hasattr(config.agent, key):
                    setattr(config.agent, key, value)
        
        if 'crypto' in data:
            for key, value in data['crypto'].items():
                if hasattr(config.crypto, key):
                    setattr(config.crypto, key, value)
        
        if 'storage' in data:
            for key, value in data['storage'].items():
                if hasattr(config.storage, key):
                    setattr(config.storage, key, value)
        
        return config
    
    def validate(self) -> bool:
        """Validate configuration values"""
        errors = []
        
        # Validate EventBus config
        if not (1 <= self.eventbus.port <= 65535):
            errors.append(f"Invalid EventBus port: {self.eventbus.port}")
        
        if self.eventbus.max_inflight <= 0:
            errors.append(f"Invalid max_inflight: {self.eventbus.max_inflight}")
        
        # Validate Agent config
        if self.agent.max_env_bytes <= 0:
            errors.append(f"Invalid max_env_bytes: {self.agent.max_env_bytes}")
        
        if self.agent.retry_max < 0:
            errors.append(f"Invalid retry_max: {self.agent.retry_max}")
        
        # Validate paths exist
        cert_dir = Path(self.agent.cert_dir)
        if not cert_dir.exists():
            errors.append(f"Certificate directory not found: {cert_dir}")
        
        # Create data directories if they don't exist
        for dir_path in [self.storage.data_dir, self.storage.wal_dir, self.storage.storage_dir]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
        
        if errors:
            for error in errors:
                print(f"Configuration error: {error}")
            return False
        
        return True
    
    def setup_logging(self):
        """Configure logging based on configuration"""
        import logging
        log_level = getattr(logging, self.eventbus.log_level, logging.INFO)
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s [%(name)s] %(message)s',
            level=log_level,
            force=True
        )


# Global configuration instance
_config: Optional[AmoskysConfig] = None


def get_config() -> AmoskysConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        # Try to load from config.yaml first, then fall back to environment
        config_path = Path("config/amoskys.yaml")
        if config_path.exists():
            _config = AmoskysConfig.from_yaml(str(config_path))
        else:
            _config = AmoskysConfig.from_env()
        
        # Validate configuration
        if not _config.validate():
            raise ValueError("Configuration validation failed")
        
        # Setup logging
        _config.setup_logging()
    
    return _config


def init_config(config: AmoskysConfig):
    """Initialize global configuration"""
    global _config
    _config = config


if __name__ == "__main__":
    # CLI tool for configuration management
    import argparse
    
    parser = argparse.ArgumentParser(description="Amoskys Configuration Tool")
    parser.add_argument("--dump", action="store_true", help="Dump current configuration")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")
    parser.add_argument("--config", help="Path to configuration YAML file")
    
    args = parser.parse_args()
    
    if args.config:
        config = AmoskysConfig.from_yaml(args.config)
    else:
        config = AmoskysConfig.from_env()
    
    if args.validate:
        if config.validate():
            print("✅ Configuration is valid")
        else:
            print("❌ Configuration validation failed")
            exit(1)
    
    if args.dump:
        import json
        print(json.dumps(config.__dict__, indent=2, default=str))
