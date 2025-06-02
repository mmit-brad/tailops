"""
Configuration management for tailops.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages configuration loading and validation."""
    
    DEFAULT_CONFIG_PATHS = [
        "config/tenants.yaml",
        "~/.tailops/config.yaml",
        "/etc/tailops/config.yaml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = {}
    
    def find_config_file(self) -> Optional[str]:
        """Find the configuration file in default locations."""
        if self.config_path:
            expanded_path = os.path.expanduser(self.config_path)
            if os.path.exists(expanded_path):
                return expanded_path
            else:
                raise FileNotFoundError(f"Configuration file not found: {expanded_path}")
        
        # Try default locations
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                logger.debug(f"Found config file: {expanded_path}")
                return expanded_path
        
        return None
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        config_file = self.find_config_file()
        
        if not config_file:
            logger.warning("No configuration file found, using empty config")
            return {}
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            
            self.config = config
            self.validate_config()
            logger.info(f"Configuration loaded from: {config_file}")
            return config
            
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {e}")
    
    def validate_config(self):
        """Validate the loaded configuration."""
        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")
        
        if 'tenants' in self.config:
            self.validate_tenants()
    
    def validate_tenants(self):
        """Validate tenant configurations."""
        tenants = self.config.get('tenants', {})
        
        # Handle case where tenants is None (empty YAML file or all commented)
        if tenants is None:
            self.config['tenants'] = {}
            return
            
        if not isinstance(tenants, dict):
            raise ValueError("'tenants' must be a dictionary")
        
        for tenant_name, tenant_config in tenants.items():
            if not isinstance(tenant_config, dict):
                raise ValueError(f"Tenant '{tenant_name}' configuration must be a dictionary")
            
            # Validate required fields
            required_fields = ['api_key', 'tailnet']
            for field in required_fields:
                if field not in tenant_config:
                    raise ValueError(f"Tenant '{tenant_name}' missing required field: {field}")
            
            # Validate API key format
            api_key = tenant_config['api_key']
            if not api_key.startswith('tskey-'):
                logger.warning(f"Tenant '{tenant_name}' API key doesn't start with 'tskey-'")
    
    def get_tenant_config(self, tenant_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tenant."""
        tenants = self.config.get('tenants', {})
        if tenant_name not in tenants:
            raise ValueError(f"Tenant '{tenant_name}' not found in configuration")
        return tenants[tenant_name]
    
    def list_tenants(self) -> list:
        """List all configured tenants."""
        return list(self.config.get('tenants', {}).keys())
    
    def save_config(self, config_path: Optional[str] = None):
        """Save current configuration to file."""
        if config_path:
            save_path = os.path.expanduser(config_path)
        else:
            save_path = self.find_config_file()
            if not save_path:
                # Default to config/tenants.yaml
                save_path = "config/tenants.yaml"
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to: {save_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to save configuration: {e}")
