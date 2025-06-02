"""
Tenant management commands for tailops.
"""

import click
import logging
from typing import Dict, Any

from ..api import TailscaleAPI
from ..utils.output import success, error, info, warning, print_table, confirm, prompt

logger = logging.getLogger(__name__)


@click.group()
def tenant_commands():
    """Tenant management commands."""
    pass


@tenant_commands.command('list')
@click.pass_context
def list_tenants(ctx):
    """List all configured tenants."""
    try:
        config = ctx.obj.config
        if not config or 'tenants' not in config:
            warning("No tenants configured")
            return
        
        tenants = config['tenants']
        
        headers = ['Name', 'Tailnet', 'Status', 'Description']
        rows = []
        
        for tenant_name, tenant_config in tenants.items():
            tailnet = tenant_config.get('tailnet', 'unknown')
            description = tenant_config.get('name', tenant_config.get('description', '-'))
            
            # Test connection to determine status
            try:
                api = TailscaleAPI(tenant_config['api_key'], tailnet)
                if api.test_connection():
                    status = "✓ Connected"
                else:
                    status = "✗ Failed"
            except Exception:
                status = "✗ Error"
            
            rows.append([tenant_name, tailnet, status, description])
        
        print_table(headers, rows)
        info(f"Total tenants: {len(tenants)}")
        
    except Exception as e:
        error(f"Failed to list tenants: {e}")
        if ctx.obj.debug:
            logger.exception("List tenants command failed")


@tenant_commands.command('show')
@click.argument('tenant_name')
@click.pass_context
def show_tenant(ctx, tenant_name):
    """Show detailed information about a tenant."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if tenant_name not in tenants:
            error(f"Tenant '{tenant_name}' not found")
            return
        
        tenant_config = tenants[tenant_name]
        
        # Display basic info
        info(f"Tenant: {tenant_name}")
        click.echo(f"  Name: {tenant_config.get('name', 'N/A')}")
        click.echo(f"  Tailnet: {tenant_config.get('tailnet', 'N/A')}")
        click.echo(f"  Description: {tenant_config.get('description', 'N/A')}")
        
        # Test API connection
        try:
            api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
            if api.test_connection():
                success("API connection successful")
                
                # Get device count
                devices = api.get_devices()
                info(f"Devices: {len(devices)}")
                
                # Show settings
                settings = tenant_config.get('settings', {})
                if settings:
                    click.echo("\nSettings:")
                    for key, value in settings.items():
                        click.echo(f"  {key}: {value}")
                
            else:
                error("API connection failed")
                
        except Exception as e:
            error(f"API connection error: {e}")
            
    except Exception as e:
        error(f"Failed to show tenant: {e}")
        if ctx.obj.debug:
            logger.exception("Show tenant command failed")


@tenant_commands.command('add')
@click.argument('tenant_name')
@click.option('--api-key', help='Tailscale API key')
@click.option('--tailnet', help='Tailnet name')
@click.option('--name', help='Display name for the tenant')
@click.option('--description', help='Description of the tenant')
@click.pass_context
def add_tenant(ctx, tenant_name, api_key, tailnet, name, description):
    """Add a new tenant configuration."""
    try:
        config = ctx.obj.config
        if 'tenants' not in config:
            config['tenants'] = {}
        
        tenants = config['tenants']
        
        if tenant_name in tenants:
            error(f"Tenant '{tenant_name}' already exists")
            return
        
        # Prompt for missing information
        if not api_key:
            api_key = prompt("Tailscale API key", hide_input=True)
        
        if not tailnet:
            tailnet = prompt("Tailnet name (e.g., example.ts.net)")
        
        if not name:
            name = prompt("Display name", default=tenant_name)
        
        if not description:
            description = prompt("Description", default="")
        
        # Validate API key
        if not api_key.startswith('tskey-'):
            warning("API key doesn't start with 'tskey-', this might be incorrect")
        
        # Test the API connection
        try:
            api = TailscaleAPI(api_key, tailnet)
            if not api.test_connection():
                error("Failed to connect to Tailscale API with provided credentials")
                if not confirm("Add tenant anyway?"):
                    return
        except Exception as e:
            error(f"API connection test failed: {e}")
            if not confirm("Add tenant anyway?"):
                return
        
        # Add tenant to config
        tenant_config = {
            'name': name,
            'api_key': api_key,
            'tailnet': tailnet,
            'description': description,
            'settings': {
                'auto_approve': False,
                'dns_enabled': True
            }
        }
        
        tenants[tenant_name] = tenant_config
        
        # Save configuration
        ctx.obj.config_manager.config = config
        ctx.obj.config_manager.save_config()
        
        success(f"Tenant '{tenant_name}' added successfully")
        
    except Exception as e:
        error(f"Failed to add tenant: {e}")
        if ctx.obj.debug:
            logger.exception("Add tenant command failed")


@tenant_commands.command('remove')
@click.argument('tenant_name')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def remove_tenant(ctx, tenant_name, force):
    """Remove a tenant configuration."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if tenant_name not in tenants:
            error(f"Tenant '{tenant_name}' not found")
            return
        
        if not force:
            if not confirm(f"Remove tenant '{tenant_name}'?"):
                info("Operation cancelled")
                return
        
        # Remove tenant
        del tenants[tenant_name]
        
        # Save configuration
        ctx.obj.config_manager.config = config
        ctx.obj.config_manager.save_config()
        
        success(f"Tenant '{tenant_name}' removed successfully")
        
    except Exception as e:
        error(f"Failed to remove tenant: {e}")
        if ctx.obj.debug:
            logger.exception("Remove tenant command failed")


@tenant_commands.command('test')
@click.argument('tenant_name', required=False)
@click.pass_context
def test_tenant(ctx, tenant_name):
    """Test API connection for tenant(s)."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if not tenants:
            warning("No tenants configured")
            return
        
        # Test specific tenant or all tenants
        test_tenants = {}
        if tenant_name:
            if tenant_name not in tenants:
                error(f"Tenant '{tenant_name}' not found")
                return
            test_tenants[tenant_name] = tenants[tenant_name]
        else:
            test_tenants = tenants
        
        headers = ['Tenant', 'Status', 'Devices', 'Message']
        rows = []
        
        for name, tenant_config in test_tenants.items():
            try:
                api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
                devices = api.get_devices()
                rows.append([name, "✓ Connected", len(devices), "OK"])
                
            except ValueError as e:
                rows.append([name, "✗ Failed", "-", str(e)])
            except Exception as e:
                rows.append([name, "✗ Error", "-", str(e)])
        
        print_table(headers, rows)
        
    except Exception as e:
        error(f"Failed to test tenant(s): {e}")
        if ctx.obj.debug:
            logger.exception("Test tenant command failed")
