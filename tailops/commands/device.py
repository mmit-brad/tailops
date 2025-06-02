"""
Device management commands for tailops.
"""

import click
import logging
from typing import Dict, Any, List
from datetime import datetime

from ..api import TailscaleAPI
from ..utils.output import success, error, info, warning, print_table, confirm, prompt

logger = logging.getLogger(__name__)


@click.group()
def device_commands():
    """Device management commands."""
    pass


@device_commands.command('list')
@click.option('--tenant', help='Filter by specific tenant')
@click.option('--status', type=click.Choice(['online', 'offline', 'all']), default='all', help='Filter by device status')
@click.pass_context
def list_devices(ctx, tenant, status):
    """List devices across all tenants or for a specific tenant."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if not tenants:
            warning("No tenants configured")
            return
        
        # Filter tenants if specified
        if tenant:
            if tenant not in tenants:
                error(f"Tenant '{tenant}' not found")
                return
            selected_tenants = {tenant: tenants[tenant]}
        else:
            selected_tenants = tenants
        
        headers = ['Tenant', 'Device Name', 'IP Address', 'Status', 'OS', 'Last Seen']
        rows = []
        
        for tenant_name, tenant_config in selected_tenants.items():
            try:
                api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
                devices = api.get_devices()
                
                for device in devices:
                    device_name = device.get('name', 'Unknown')
                    ip_address = ', '.join(device.get('addresses', []))
                    online = device.get('online', False)
                    device_status = "Online" if online else "Offline"
                    os_info = device.get('os', 'Unknown')
                    
                    # Parse last seen
                    last_seen = device.get('lastSeen', '')
                    if last_seen:
                        try:
                            dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                            last_seen_str = dt.strftime('%Y-%m-%d %H:%M')
                        except:
                            last_seen_str = last_seen
                    else:
                        last_seen_str = 'Never'
                    
                    # Apply status filter
                    if status != 'all':
                        if (status == 'online' and not online) or (status == 'offline' and online):
                            continue
                    
                    rows.append([tenant_name, device_name, ip_address, device_status, os_info, last_seen_str])
                    
            except Exception as e:
                error(f"Failed to get devices for tenant '{tenant_name}': {e}")
                continue
        
        if rows:
            print_table(headers, rows)
            info(f"Total devices: {len(rows)}")
        else:
            warning("No devices found")
            
    except Exception as e:
        error(f"Failed to list devices: {e}")
        if ctx.obj.debug:
            logger.exception("List devices command failed")


@device_commands.command('show')
@click.argument('device_name')
@click.option('--tenant', help='Specify tenant (required if device name is not unique)')
@click.pass_context
def show_device(ctx, device_name, tenant):
    """Show detailed information about a device."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if not tenants:
            warning("No tenants configured")
            return
        
        # Find device across tenants
        found_devices = []
        
        search_tenants = {tenant: tenants[tenant]} if tenant else tenants
        
        for tenant_name, tenant_config in search_tenants.items():
            try:
                api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
                devices = api.get_devices()
                
                for device in devices:
                    if device.get('name', '').lower() == device_name.lower():
                        found_devices.append((tenant_name, device, api))
                        
            except Exception as e:
                error(f"Failed to search in tenant '{tenant_name}': {e}")
                continue
        
        if not found_devices:
            error(f"Device '{device_name}' not found")
            return
        
        if len(found_devices) > 1 and not tenant:
            error(f"Multiple devices named '{device_name}' found. Please specify --tenant")
            for tenant_name, device, _ in found_devices:
                info(f"  Found in tenant: {tenant_name}")
            return
        
        tenant_name, device, api = found_devices[0]
        
        # Display device information
        info(f"Device: {device.get('name', 'Unknown')}")
        click.echo(f"  Tenant: {tenant_name}")
        click.echo(f"  ID: {device.get('id', 'N/A')}")
        click.echo(f"  Addresses: {', '.join(device.get('addresses', []))}")
        click.echo(f"  Status: {'Online' if device.get('online', False) else 'Offline'}")
        click.echo(f"  OS: {device.get('os', 'Unknown')}")
        click.echo(f"  Hostname: {device.get('hostname', 'N/A')}")
        click.echo(f"  User: {device.get('user', 'N/A')}")
        click.echo(f"  Authorized: {'Yes' if device.get('authorized', False) else 'No'}")
        click.echo(f"  Key Expiry Warning: {'Yes' if device.get('keyExpiryDisabled', False) else 'No'}")
        
        # Show last seen
        last_seen = device.get('lastSeen', '')
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                last_seen_str = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                last_seen_str = last_seen
            click.echo(f"  Last Seen: {last_seen_str}")
        
        # Show tags if any
        tags = device.get('tags', [])
        if tags:
            click.echo(f"  Tags: {', '.join(tags)}")
        
        # Show advertised routes
        try:
            routes = api.get_device_routes(device['id'])
            if routes:
                click.echo("  Advertised Routes:")
                for route in routes:
                    enabled = "✓" if route.get('enabled', False) else "✗"
                    click.echo(f"    {enabled} {route.get('route', 'N/A')}")
        except:
            pass
            
    except Exception as e:
        error(f"Failed to show device: {e}")
        if ctx.obj.debug:
            logger.exception("Show device command failed")


@device_commands.command('authorize')
@click.argument('device_name')
@click.option('--tenant', help='Specify tenant (required if device name is not unique)')
@click.pass_context
def authorize_device(ctx, device_name, tenant):
    """Authorize a device."""
    try:
        device_info = _find_device(ctx, device_name, tenant)
        if not device_info:
            return
        
        tenant_name, device, api = device_info
        
        if device.get('authorized', False):
            warning(f"Device '{device_name}' is already authorized")
            return
        
        # Authorize the device
        result = api.authorize_device(device['id'])
        success(f"Device '{device_name}' authorized successfully")
        
    except Exception as e:
        error(f"Failed to authorize device: {e}")
        if ctx.obj.debug:
            logger.exception("Authorize device command failed")


@device_commands.command('remove')
@click.argument('device_name')
@click.option('--tenant', help='Specify tenant (required if device name is not unique)')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def remove_device(ctx, device_name, tenant, force):
    """Remove a device from its tailnet."""
    try:
        device_info = _find_device(ctx, device_name, tenant)
        if not device_info:
            return
        
        tenant_name, device, api = device_info
        
        if not force:
            if not confirm(f"Remove device '{device_name}' from tenant '{tenant_name}'?"):
                info("Operation cancelled")
                return
        
        # Remove the device
        api.delete_device(device['id'])
        success(f"Device '{device_name}' removed successfully")
        
    except Exception as e:
        error(f"Failed to remove device: {e}")
        if ctx.obj.debug:
            logger.exception("Remove device command failed")


@device_commands.command('routes')
@click.argument('device_name')
@click.option('--tenant', help='Specify tenant (required if device name is not unique)')
@click.option('--add', multiple=True, help='Add subnet routes (can be used multiple times)')
@click.option('--remove', multiple=True, help='Remove subnet routes (can be used multiple times)')
@click.pass_context
def manage_routes(ctx, device_name, tenant, add, remove):
    """Manage subnet routes for a device."""
    try:
        device_info = _find_device(ctx, device_name, tenant)
        if not device_info:
            return
        
        tenant_name, device, api = device_info
        
        # Get current routes
        current_routes = api.get_device_routes(device['id'])
        
        if not add and not remove:
            # Just show current routes
            if current_routes:
                headers = ['Route', 'Enabled', 'Approved']
                rows = []
                for route in current_routes:
                    enabled = "✓" if route.get('enabled', False) else "✗"
                    approved = "✓" if route.get('approved', False) else "✗"
                    rows.append([route.get('route', 'N/A'), enabled, approved])
                
                print_table(headers, rows)
            else:
                info("No routes configured for this device")
            return
        
        # Modify routes
        route_list = [r.get('route') for r in current_routes if r.get('route')]
        
        # Add new routes
        for route in add:
            if route not in route_list:
                route_list.append(route)
                info(f"Adding route: {route}")
        
        # Remove routes
        for route in remove:
            if route in route_list:
                route_list.remove(route)
                info(f"Removing route: {route}")
        
        # Update routes
        result = api.set_device_routes(device['id'], route_list)
        success("Device routes updated successfully")
        
    except Exception as e:
        error(f"Failed to manage device routes: {e}")
        if ctx.obj.debug:
            logger.exception("Manage routes command failed")


def _find_device(ctx, device_name: str, tenant: str = None):
    """Helper function to find a device across tenants."""
    config = ctx.obj.config
    tenants = config.get('tenants', {})
    
    if not tenants:
        warning("No tenants configured")
        return None
    
    # Find device across tenants
    found_devices = []
    
    search_tenants = {tenant: tenants[tenant]} if tenant else tenants
    
    for tenant_name, tenant_config in search_tenants.items():
        try:
            api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
            devices = api.get_devices()
            
            for device in devices:
                if device.get('name', '').lower() == device_name.lower():
                    found_devices.append((tenant_name, device, api))
                    
        except Exception as e:
            error(f"Failed to search in tenant '{tenant_name}': {e}")
            continue
    
    if not found_devices:
        error(f"Device '{device_name}' not found")
        return None
    
    if len(found_devices) > 1 and not tenant:
        error(f"Multiple devices named '{device_name}' found. Please specify --tenant")
        for tenant_name, device, _ in found_devices:
            info(f"  Found in tenant: {tenant_name}")
        return None
    
    return found_devices[0]
