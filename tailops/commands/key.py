"""
API key management and rotation commands for tailops.
"""

import os
import time
import click
import logging
import getpass
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from ..api import TailscaleAPI
from ..config import ConfigManager
from ..secrets import ConfigEncryption, get_password_from_env, is_encrypted_file
from ..utils.output import success, error, info, warning, confirm, prompt, print_table
from ..utils.formatter import OutputFormatter

logger = logging.getLogger(__name__)


class KeyRotationManager:
    """Manages API key rotation operations with audit logging."""
    
    def __init__(self, log_dir: Optional[str] = None):
        """Initialize the key rotation manager."""
        if log_dir is None:
            log_dir = os.path.expanduser("~/.tailops/logs")
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.rotation_log = self.log_dir / "rotation.log"
    
    def _log_rotation(self, operation: str, tenant: str, success: bool, details: str = ""):
        """Log key rotation operations for audit trail."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        status = "SUCCESS" if success else "FAILED"
        log_entry = f"{timestamp} - {operation} - {status} - {tenant}"
        if details:
            log_entry += f" - {details}"
        
        try:
            with open(self.rotation_log, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            logger.warning(f"Failed to write rotation log: {e}")
    
    def rotate_tenant_key(self, tenant_name: str, tenant_config: Dict[str, Any], 
                         config_manager: ConfigManager, dry_run: bool = False) -> bool:
        """
        Rotate API key for a single tenant.
        
        Args:
            tenant_name: Name of the tenant
            tenant_config: Tenant configuration
            config_manager: Configuration manager instance
            dry_run: If True, only simulate the rotation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            old_api_key = tenant_config['api_key']
            tailnet = tenant_config['tailnet']
            
            if dry_run:
                info(f"[DRY RUN] Would rotate key for tenant '{tenant_name}'")
                self._log_rotation("DRY_RUN", tenant_name, True, "Simulated rotation")
                return True
            
            # Step 1: Create new API key
            api = TailscaleAPI(old_api_key, tailnet)
            description = f"tailops-rotation-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            
            info(f"Creating new API key for tenant '{tenant_name}'...")
            new_key_response = api.create_api_key(description=description)
            new_api_key = new_key_response.get('key')
            
            if not new_api_key:
                raise RuntimeError("Failed to create new API key")
            
            # Step 2: Test new key
            info(f"Testing new API key for tenant '{tenant_name}'...")
            test_result = api.test_api_key_permissions(new_api_key)
            
            if not test_result.get('valid', False):
                raise RuntimeError(f"New API key validation failed: {test_result.get('error', 'Unknown error')}")
            
            # Step 3: Update configuration
            info(f"Updating configuration for tenant '{tenant_name}'...")
            config = config_manager.config
            config['tenants'][tenant_name]['api_key'] = new_api_key
            
            # Save configuration (handles encryption automatically if needed)
            config_manager.save_config()
            
            # Step 4: Archive old key metadata
            old_key_info = {
                'tenant': tenant_name,
                'old_key_prefix': old_api_key[:20] + "...",
                'new_key_prefix': new_api_key[:20] + "...",
                'rotated_at': datetime.utcnow().isoformat() + "Z",
                'description': description
            }
            
            # Step 5: Expire old key (optional - let it expire naturally for safety)
            # We could delete the old key here, but it's safer to let it expire
            # This prevents issues if the config update failed somehow
            
            success(f"Successfully rotated API key for tenant '{tenant_name}'")
            self._log_rotation("ROTATE", tenant_name, True, 
                             f"Old: {old_key_info['old_key_prefix']}, New: {old_key_info['new_key_prefix']}")
            
            return True
            
        except Exception as e:
            error(f"Failed to rotate key for tenant '{tenant_name}': {e}")
            self._log_rotation("ROTATE", tenant_name, False, str(e))
            return False


@click.group()
def key_commands():
    """API key management and rotation commands."""
    pass


@key_commands.command('list')
@click.option('--tenant', help='Show keys for specific tenant only')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.pass_context
def list_keys(ctx, tenant, output_json):
    """List API keys for tenants."""
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
        
        keys_data = []
        
        for tenant_name, tenant_config in selected_tenants.items():
            try:
                api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
                
                # Get current key info
                current_key = tenant_config['api_key']
                key_prefix = current_key[:20] + "..." if len(current_key) > 20 else current_key
                
                # Test key validity
                test_result = api.test_api_key_permissions()
                
                keys_data.append({
                    'tenant': tenant_name,
                    'key_prefix': key_prefix,
                    'tailnet': tenant_config['tailnet'],
                    'status': 'valid' if test_result.get('valid', False) else 'invalid',
                    'device_count': test_result.get('device_count', 0),
                    'last_tested': test_result.get('tested_at', ''),
                    'error': test_result.get('error', '')
                })
                
            except Exception as e:
                keys_data.append({
                    'tenant': tenant_name,
                    'key_prefix': 'ERROR',
                    'tailnet': tenant_config.get('tailnet', 'unknown'),
                    'status': 'error',
                    'device_count': 0,
                    'last_tested': datetime.utcnow().isoformat() + 'Z',
                    'error': str(e)
                })
        
        # Format output
        formatter = OutputFormatter("json" if output_json else "table")
        if output_json:
            formatter.output_test_results(keys_data, "key list")
        else:
            if not keys_data:
                warning("No API keys found")
                return
            
            headers = ['Tenant', 'Key Prefix', 'Tailnet', 'Status', 'Devices']
            rows = []
            for key_info in keys_data:
                status_display = "✓ Valid" if key_info['status'] == 'valid' else "✗ Invalid"
                if key_info['status'] == 'error':
                    status_display = "✗ Error"
                
                rows.append([
                    key_info['tenant'],
                    key_info['key_prefix'],
                    key_info['tailnet'],
                    status_display,
                    str(key_info['device_count'])
                ])
            
            print_table(headers, rows)
            info(f"Total tenants: {len(keys_data)}")
        
    except Exception as e:
        error(f"Failed to list keys: {e}")
        if ctx.obj.debug:
            logger.exception("List keys command failed")


@key_commands.command('rotate')
@click.option('--tenant', required=True, help='Tenant to rotate key for')
@click.option('--dry-run', is_flag=True, help='Show what would be done without making changes')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def rotate_key(ctx, tenant, dry_run, force):
    """Rotate API key for a specific tenant."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if tenant not in tenants:
            error(f"Tenant '{tenant}' not found")
            return
        
        tenant_config = tenants[tenant]
        
        if dry_run:
            info(f"[DRY RUN] Key rotation for tenant '{tenant}':")
            info(f"  Current key: {tenant_config['api_key'][:20]}...")
            info(f"  Tailnet: {tenant_config['tailnet']}")
            info("  Would create new key, test it, and update configuration")
            return
        
        if not force:
            warning(f"This will rotate the API key for tenant '{tenant}'")
            info("The old key will remain valid until it expires naturally")
            if not confirm("Continue with key rotation?"):
                info("Operation cancelled")
                return
        
        # Perform rotation
        rotation_manager = KeyRotationManager()
        success = rotation_manager.rotate_tenant_key(
            tenant, tenant_config, ctx.obj.config_manager, dry_run=False
        )
        
        if success:
            success(f"API key rotated successfully for tenant '{tenant}'")
            info("The new key is now active in your configuration")
            warning("Update any external systems that use the old API key")
        else:
            error(f"Failed to rotate API key for tenant '{tenant}'")
        
    except Exception as e:
        error(f"Key rotation failed: {e}")
        if ctx.obj.debug:
            logger.exception("Rotate key command failed")


@key_commands.command('rotate-all')
@click.option('--dry-run', is_flag=True, help='Show what would be done without making changes')
@click.option('--delay', default=5, help='Delay between rotations in seconds (default: 5)')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def rotate_all_keys(ctx, dry_run, delay, force):
    """Rotate API keys for all tenants."""
    try:
        config = ctx.obj.config
        tenants = config.get('tenants', {})
        
        if not tenants:
            warning("No tenants configured")
            return
        
        if dry_run:
            info(f"[DRY RUN] Would rotate keys for {len(tenants)} tenants:")
            for tenant_name in tenants.keys():
                info(f"  - {tenant_name}")
            info(f"  Delay between rotations: {delay} seconds")
            return
        
        if not force:
            warning(f"This will rotate API keys for ALL {len(tenants)} tenants")
            info(f"Delay between rotations: {delay} seconds")
            if not confirm("Continue with bulk key rotation?"):
                info("Operation cancelled")
                return
        
        # Perform bulk rotation
        rotation_manager = KeyRotationManager()
        successful = 0
        failed = 0
        
        for i, (tenant_name, tenant_config) in enumerate(tenants.items()):
            info(f"Rotating key for tenant '{tenant_name}' ({i+1}/{len(tenants)})...")
            
            success = rotation_manager.rotate_tenant_key(
                tenant_name, tenant_config, ctx.obj.config_manager, dry_run=False
            )
            
            if success:
                successful += 1
            else:
                failed += 1
            
            # Add delay between rotations (except for the last one)
            if i < len(tenants) - 1:
                info(f"Waiting {delay} seconds before next rotation...")
                time.sleep(delay)
        
        # Summary
        info(f"Bulk key rotation completed:")
        success(f"  Successful: {successful}")
        if failed > 0:
            error(f"  Failed: {failed}")
        
        if successful > 0:
            warning("Remember to update any external systems with the new API keys")
        
    except Exception as e:
        error(f"Bulk key rotation failed: {e}")
        if ctx.obj.debug:
            logger.exception("Rotate all keys command failed")


@key_commands.command('test')
@click.option('--tenant', help='Test specific tenant only')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.pass_context
def test_keys(ctx, tenant, output_json):
    """Test API key validity for tenants."""
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
        
        test_results = []
        
        for tenant_name, tenant_config in selected_tenants.items():
            try:
                api = TailscaleAPI(tenant_config['api_key'], tenant_config['tailnet'])
                test_result = api.test_api_key_permissions()
                
                test_results.append({
                    'tenant': tenant_name,
                    'status': 'valid' if test_result.get('valid', False) else 'invalid',
                    'device_count': test_result.get('device_count', 0),
                    'can_list_devices': test_result.get('can_list_devices', False),
                    'can_manage_keys': test_result.get('can_manage_keys', False),
                    'tested_at': test_result.get('tested_at', ''),
                    'error': test_result.get('error', '')
                })
                
            except Exception as e:
                test_results.append({
                    'tenant': tenant_name,
                    'status': 'error',
                    'device_count': 0,
                    'can_list_devices': False,
                    'can_manage_keys': False,
                    'tested_at': datetime.utcnow().isoformat() + 'Z',
                    'error': str(e)
                })
        
        # Format output
        formatter = OutputFormatter("json" if output_json else "table")
        if output_json:
            formatter.output_test_results(test_results, "key test")
        else:
            headers = ['Tenant', 'Status', 'Devices', 'List', 'Manage', 'Message']
            rows = []
            for result in test_results:
                status_display = "✓ Valid" if result['status'] == 'valid' else "✗ Invalid"
                if result['status'] == 'error':
                    status_display = "✗ Error"
                
                list_perm = "✓" if result['can_list_devices'] else "✗"
                manage_perm = "✓" if result['can_manage_keys'] else "✗"
                message = result['error'] if result['error'] else "OK"
                
                rows.append([
                    result['tenant'],
                    status_display,
                    str(result['device_count']),
                    list_perm,
                    manage_perm,
                    message
                ])
            
            print_table(headers, rows)
        
    except Exception as e:
        error(f"Failed to test keys: {e}")
        if ctx.obj.debug:
            logger.exception("Test keys command failed")


@key_commands.command('archive')
@click.option('--tenant', help='Archive keys for specific tenant only')
@click.option('--days', default=90, help='Archive keys older than this many days (default: 90)')
@click.option('--dry-run', is_flag=True, help='Show what would be archived without making changes')
@click.pass_context
def archive_keys(ctx, tenant, days, dry_run):
    """Archive old key rotation logs."""
    try:
        log_dir = Path.home() / ".tailops" / "logs"
        rotation_log = log_dir / "rotation.log"
        
        if not rotation_log.exists():
            info("No rotation log found - nothing to archive")
            return
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        archive_path = log_dir / f"rotation-archive-{datetime.utcnow().strftime('%Y%m%d')}.log"
        
        if dry_run:
            info(f"[DRY RUN] Would archive rotation logs older than {days} days")
            info(f"  Cutoff date: {cutoff_date.isoformat()}")
            info(f"  Archive would be saved to: {archive_path}")
            return
        
        # Read current log and filter
        current_entries = []
        archive_entries = []
        
        try:
            with open(rotation_log, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse timestamp from log entry
                    try:
                        timestamp_str = line.split(' - ')[0]
                        entry_date = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        
                        if entry_date < cutoff_date:
                            archive_entries.append(line)
                        else:
                            current_entries.append(line)
                    except:
                        # Keep unparseable lines in current log
                        current_entries.append(line)
        
        except Exception as e:
            error(f"Failed to read rotation log: {e}")
            return
        
        if not archive_entries:
            info(f"No rotation log entries older than {days} days found")
            return
        
        # Write archive file
        with open(archive_path, 'w', encoding='utf-8') as f:
            f.write(f"# Archived rotation log entries older than {days} days\n")
            f.write(f"# Archived on: {datetime.utcnow().isoformat()}Z\n")
            f.write(f"# Original log: {rotation_log}\n\n")
            for entry in archive_entries:
                f.write(entry + "\n")
        
        # Update current log
        with open(rotation_log, 'w', encoding='utf-8') as f:
            for entry in current_entries:
                f.write(entry + "\n")
        
        success(f"Archived {len(archive_entries)} log entries to {archive_path}")
        info(f"Kept {len(current_entries)} recent entries in rotation log")
        
    except Exception as e:
        error(f"Failed to archive keys: {e}")
        if ctx.obj.debug:
            logger.exception("Archive keys command failed")
