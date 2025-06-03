"""
Configuration encryption commands for tailops.
"""

import os
import click
import logging
import getpass
from typing import Optional

from ..secrets import ConfigEncryption, get_password_from_env, is_encrypted_file
from ..utils.output import success, error, info, warning, confirm, prompt

logger = logging.getLogger(__name__)


@click.group()
def secrets_commands():
    """Configuration encryption and security commands."""
    pass


def _get_password(prompt_text: str = "Password", confirm_password: bool = False) -> str:
    """Get password from environment variable or interactive prompt."""
    # Try environment variable first
    env_password = get_password_from_env()
    if env_password:
        info("Using password from TAILOPS_SECRET environment variable")
        return env_password
    
    # Interactive prompt
    password = getpass.getpass(f"{prompt_text}: ")
    if not password:
        raise click.Abort("Password is required")
    
    if confirm_password:
        confirm_pass = getpass.getpass("Confirm password: ")
        if password != confirm_pass:
            error("Passwords do not match")
            raise click.Abort()
    
    return password


@secrets_commands.command('encrypt')
@click.argument('config_file')
@click.option('--output', '-o', help='Output file path (default: adds .enc.yaml extension)')
@click.option('--password-env', is_flag=True, help='Use TAILOPS_SECRET environment variable')
@click.option('--force', is_flag=True, help='Overwrite existing encrypted file')
@click.pass_context
def encrypt_config(ctx, config_file, output, password_env, force):
    """Encrypt a configuration file."""
    try:
        # Check if input file exists
        if not os.path.exists(config_file):
            error(f"Configuration file not found: {config_file}")
            return
        
        # Check if already encrypted
        if is_encrypted_file(config_file):
            warning(f"File '{config_file}' appears to already be encrypted")
            if not confirm("Continue anyway?"):
                return
        
        # Determine output path
        if not output:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                output = config_file + ConfigEncryption.ENCRYPTED_EXTENSION
            else:
                output = config_file + ConfigEncryption.ENCRYPTED_EXTENSION
        
        # Check if output exists
        if os.path.exists(output) and not force:
            error(f"Output file already exists: {output}")
            info("Use --force to overwrite or specify a different output path")
            return
        
        # Get password
        if password_env:
            password = get_password_from_env()
            if not password:
                error("TAILOPS_SECRET environment variable not set")
                return
        else:
            password = _get_password("Encryption password", confirm_password=True)
        
        # Perform encryption
        encryption = ConfigEncryption()
        encrypted_file = encryption.encrypt_file(config_file, password, output)
        
        success(f"Configuration encrypted successfully")
        info(f"Encrypted file: {encrypted_file}")
        info(f"Backup created: {config_file}{ConfigEncryption.BACKUP_EXTENSION}")
        warning("Store your password securely - it cannot be recovered if lost!")
        
    except Exception as e:
        error(f"Encryption failed: {e}")
        if ctx.obj.debug:
            logger.exception("Encrypt command failed")


@secrets_commands.command('decrypt')
@click.argument('encrypted_file')
@click.option('--output', '-o', help='Output file path (prints to stdout if not specified)')
@click.option('--password-env', is_flag=True, help='Use TAILOPS_SECRET environment variable')
@click.pass_context
def decrypt_config(ctx, encrypted_file, output, password_env):
    """Decrypt a configuration file."""
    try:
        # Check if input file exists
        if not os.path.exists(encrypted_file):
            error(f"Encrypted file not found: {encrypted_file}")
            return
        
        # Verify it's an encrypted file
        if not is_encrypted_file(encrypted_file):
            error(f"File '{encrypted_file}' is not a valid encrypted configuration file")
            return
        
        # Get password
        if password_env:
            password = get_password_from_env()
            if not password:
                error("TAILOPS_SECRET environment variable not set")
                return
        else:
            password = _get_password("Decryption password")
        
        # Perform decryption
        encryption = ConfigEncryption()
        decrypted_content = encryption.decrypt_file(encrypted_file, password, output)
        
        if output:
            success(f"Configuration decrypted successfully")
            info(f"Decrypted file: {output}")
        else:
            # Print to stdout
            click.echo(decrypted_content)
        
    except ValueError as e:
        if "Invalid password" in str(e):
            error("Invalid password or corrupted file")
        else:
            error(f"Decryption failed: {e}")
    except Exception as e:
        error(f"Decryption failed: {e}")
        if ctx.obj.debug:
            logger.exception("Decrypt command failed")


@secrets_commands.command('info')
@click.argument('encrypted_file')
@click.pass_context
def file_info(ctx, encrypted_file):
    """Show information about an encrypted file."""
    try:
        # Check if file exists
        if not os.path.exists(encrypted_file):
            error(f"File not found: {encrypted_file}")
            return
        
        # Verify it's an encrypted file
        if not is_encrypted_file(encrypted_file):
            error(f"File '{encrypted_file}' is not a valid encrypted configuration file")
            return
        
        # Get file information
        encryption = ConfigEncryption()
        file_info = encryption.get_file_info(encrypted_file)
        
        # Display information
        info("Encrypted File Information:")
        click.echo(f"  File Path: {file_info['file_path']}")
        click.echo(f"  File Size: {file_info['file_size']} bytes")
        click.echo(f"  Modified: {file_info['modified_time']}")
        click.echo(f"  Encryption Version: {file_info['encryption_version']}")
        click.echo(f"  Algorithm: {file_info['algorithm']}")
        click.echo(f"  Key Derivation: {file_info['kdf']}")
        click.echo(f"  Iterations: {file_info['iterations']:,}")
        click.echo(f"  Encrypted At: {file_info['encrypted_at']}")
        click.echo(f"  Original File: {file_info['original_file']}")
        
    except Exception as e:
        error(f"Failed to get file information: {e}")
        if ctx.obj.debug:
            logger.exception("Info command failed")


@secrets_commands.command('verify')
@click.argument('encrypted_file')
@click.option('--password-env', is_flag=True, help='Use TAILOPS_SECRET environment variable')
@click.pass_context
def verify_file(ctx, encrypted_file, password_env):
    """Verify that an encrypted file can be decrypted."""
    try:
        # Check if file exists
        if not os.path.exists(encrypted_file):
            error(f"File not found: {encrypted_file}")
            return
        
        # Verify it's an encrypted file
        if not is_encrypted_file(encrypted_file):
            error(f"File '{encrypted_file}' is not a valid encrypted configuration file")
            return
        
        # Get password
        if password_env:
            password = get_password_from_env()
            if not password:
                error("TAILOPS_SECRET environment variable not set")
                return
        else:
            password = _get_password("Password to verify")
        
        # Verify file
        encryption = ConfigEncryption()
        is_valid = encryption.verify_file(encrypted_file, password)
        
        if is_valid:
            success(f"File '{encrypted_file}' verification successful")
            info("The file can be decrypted with the provided password")
        else:
            error(f"File '{encrypted_file}' verification failed")
            warning("Invalid password or corrupted file")
        
    except Exception as e:
        error(f"Verification failed: {e}")
        if ctx.obj.debug:
            logger.exception("Verify command failed")


@secrets_commands.command('rotate')
@click.argument('encrypted_file')
@click.option('--password-env', is_flag=True, help='Use TAILOPS_SECRET environment variable for old password')
@click.pass_context
def rotate_password(ctx, encrypted_file, password_env):
    """Change the password of an encrypted file."""
    try:
        # Check if file exists
        if not os.path.exists(encrypted_file):
            error(f"File not found: {encrypted_file}")
            return
        
        # Verify it's an encrypted file
        if not is_encrypted_file(encrypted_file):
            error(f"File '{encrypted_file}' is not a valid encrypted configuration file")
            return
        
        # Get old password
        if password_env:
            old_password = get_password_from_env()
            if not old_password:
                error("TAILOPS_SECRET environment variable not set")
                return
        else:
            old_password = _get_password("Current password")
        
        # Get new password
        new_password = _get_password("New password", confirm_password=True)
        
        if old_password == new_password:
            warning("New password is the same as the current password")
            if not confirm("Continue anyway?"):
                return
        
        # Change password
        encryption = ConfigEncryption()
        encryption.change_password(encrypted_file, old_password, new_password)
        
        success(f"Password changed successfully for '{encrypted_file}'")
        warning("Make sure to update any stored passwords or environment variables")
        
    except ValueError as e:
        if "Invalid password" in str(e):
            error("Current password is incorrect")
        else:
            error(f"Password rotation failed: {e}")
    except Exception as e:
        error(f"Password rotation failed: {e}")
        if ctx.obj.debug:
            logger.exception("Rotate command failed")


@secrets_commands.command('migrate')
@click.argument('config_file')
@click.option('--password-env', is_flag=True, help='Use TAILOPS_SECRET environment variable')
@click.option('--keep-original', is_flag=True, help='Keep original file (default: creates backup)')
@click.pass_context
def migrate_config(ctx, config_file, password_env, keep_original):
    """Migrate a plain text configuration to encrypted format."""
    try:
        # Check if input file exists
        if not os.path.exists(config_file):
            error(f"Configuration file not found: {config_file}")
            return
        
        # Check if already encrypted
        if is_encrypted_file(config_file):
            error(f"File '{config_file}' is already encrypted")
            info("Use 'tailops secrets decrypt' to convert back to plain text")
            return
        
        info(f"Migrating '{config_file}' to encrypted format...")
        
        # Get password
        if password_env:
            password = get_password_from_env()
            if not password:
                error("TAILOPS_SECRET environment variable not set")
                return
        else:
            password = _get_password("Encryption password", confirm_password=True)
        
        # Create encrypted version
        encryption = ConfigEncryption()
        encrypted_file = encryption.encrypt_file(config_file, password)
        
        success(f"Migration completed successfully")
        info(f"Encrypted file: {encrypted_file}")
        
        if keep_original:
            info(f"Original file preserved: {config_file}")
        else:
            info(f"Original file backed up: {config_file}{ConfigEncryption.BACKUP_EXTENSION}")
        
        warning("Store your password securely - it cannot be recovered if lost!")
        
    except Exception as e:
        error(f"Migration failed: {e}")
        if ctx.obj.debug:
            logger.exception("Migrate command failed")
