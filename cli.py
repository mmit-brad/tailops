#!/usr/bin/env python3
"""
tailops - Multi-tenant CLI and API toolkit for managing Tailscale tailnets at MSP scale.
"""

import os
import sys
import yaml
import click
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the tailops package to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from tailops.config import ConfigManager
    from tailops.api import TailscaleAPI
    from tailops.commands.tenant import tenant_commands
    from tailops.commands.device import device_commands
    from tailops.commands.secrets import secrets_commands
    from tailops.utils.output import success, error, info, warning
except ImportError as e:
    logger.error(f"Failed to import tailops modules: {e}")
    logger.info("Make sure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)


class TailopsContext:
    """Context object to share configuration across commands."""
    
    def __init__(self):
        self.config_manager = None
        self.config = None
        self.debug = False
    
    def load_config(self, config_path: Optional[str] = None):
        """Load configuration from file."""
        try:
            self.config_manager = ConfigManager(config_path)
            self.config = self.config_manager.load_config()
            return True
        except Exception as e:
            error(f"Failed to load configuration: {e}")
            return False


@click.group()
@click.option('--config', '-c', help='Path to configuration file')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def cli(ctx, config, debug):
    """Multi-tenant CLI toolkit for managing Tailscale tailnets at MSP scale."""
    ctx.ensure_object(TailopsContext)
    ctx.obj.debug = debug
    
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    # Load configuration
    if not ctx.obj.load_config(config):
        sys.exit(1)
    
    info("tailops initialized successfully")



@cli.command()
@click.pass_context
def status(ctx):
    """Show overall system status."""
    try:
        config = ctx.obj.config
        if not config or 'tenants' not in config:
            warning("No tenants configured")
            return
        
        tenant_count = len(config['tenants'])
        success(f"tailops is operational")
        info(f"Configured tenants: {tenant_count}")
        
        for tenant_name, tenant_config in config['tenants'].items():
            tailnet = tenant_config.get('tailnet', 'unknown')
            info(f"  - {tenant_name} ({tailnet})")
            
    except Exception as e:
        error(f"Failed to get status: {e}")
        if ctx.obj.debug:
            logger.exception("Status command failed")


@cli.command()
def version():
    """Show version information."""
    click.echo("tailops v1.2.0")
    click.echo("Multi-tenant Tailscale management toolkit")


# Register command groups
cli.add_command(tenant_commands, name='tenant')
cli.add_command(device_commands, name='device')
cli.add_command(secrets_commands, name='secrets')


def main():
    """Entry point for the tailops CLI application."""
    cli()


if __name__ == '__main__':
    main()
