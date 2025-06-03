"""
Configuration encryption and security utilities for tailops.
Provides secure storage of API keys and sensitive configuration data.
"""

import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError:
    raise ImportError("cryptography package required for encryption features. Install with: pip install cryptography")

logger = logging.getLogger(__name__)


class ConfigEncryption:
    """Handles encryption and decryption of configuration files."""
    
    # Encryption parameters
    SALT_LENGTH = 16
    KEY_ITERATIONS = 100000
    ENCRYPTED_EXTENSION = ".enc.yaml"
    BACKUP_EXTENSION = ".backup"
    
    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize the encryption handler.
        
        Args:
            log_dir: Directory for audit logs (defaults to ~/.tailops/logs/)
        """
        if log_dir is None:
            log_dir = os.path.expanduser("~/.tailops/logs")
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log = self.log_dir / "secrets.log"
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KEY_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _log_operation(self, operation: str, file_path: str, success: bool, details: str = ""):
        """Log encryption/decryption operations for audit trail."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        status = "SUCCESS" if success else "FAILED"
        log_entry = f"{timestamp} - {operation} - {status} - {file_path}"
        if details:
            log_entry += f" - {details}"
        
        try:
            with open(self.audit_log, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            logger.warning(f"Failed to write audit log: {e}")
    
    def encrypt_file(self, input_path: str, password: str, output_path: Optional[str] = None) -> str:
        """
        Encrypt a configuration file.
        
        Args:
            input_path: Path to the file to encrypt
            password: Encryption password
            output_path: Output path (defaults to input_path + .enc.yaml)
            
        Returns:
            Path to the encrypted file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If password is too weak
            RuntimeError: If encryption fails
        """
        input_path = os.path.abspath(input_path)
        
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Validate password strength
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Determine output path
        if output_path is None:
            if input_path.endswith('.yaml') or input_path.endswith('.yml'):
                output_path = input_path + self.ENCRYPTED_EXTENSION
            else:
                output_path = input_path + self.ENCRYPTED_EXTENSION
        
        output_path = os.path.abspath(output_path)
        backup_path = input_path + self.BACKUP_EXTENSION
        
        try:
            # Read input file
            with open(input_path, 'rb') as f:
                file_data = f.read()
            
            # Generate salt and derive key
            salt = os.urandom(self.SALT_LENGTH)
            key = self._derive_key(password, salt)
            
            # Create Fernet instance and encrypt
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(file_data)
            
            # Create metadata
            metadata = {
                "version": "1.0",
                "algorithm": "Fernet",
                "kdf": "PBKDF2HMAC-SHA256",
                "iterations": self.KEY_ITERATIONS,
                "salt": base64.b64encode(salt).decode('ascii'),
                "encrypted_at": datetime.utcnow().isoformat() + "Z",
                "original_file": os.path.basename(input_path)
            }
            
            # Combine metadata and encrypted data
            output_data = {
                "metadata": metadata,
                "encrypted_data": base64.b64encode(encrypted_data).decode('ascii')
            }
            
            # Write to temporary file first (atomic operation)
            temp_path = output_path + ".tmp"
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            
            # Create backup of original
            if os.path.exists(input_path):
                os.rename(input_path, backup_path)
            
            # Rename temp file to final output
            os.rename(temp_path, output_path)
            
            # Set secure permissions
            os.chmod(output_path, 0o600)
            
            self._log_operation("ENCRYPT", input_path, True, f"Output: {output_path}")
            logger.info(f"Successfully encrypted {input_path} -> {output_path}")
            
            return output_path
            
        except Exception as e:
            self._log_operation("ENCRYPT", input_path, False, str(e))
            # Clean up on failure
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise RuntimeError(f"Encryption failed: {e}")
    
    def decrypt_file(self, input_path: str, password: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a configuration file.
        
        Args:
            input_path: Path to the encrypted file
            password: Decryption password
            output_path: Output path (defaults to stdout if None)
            
        Returns:
            Decrypted content as string
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If file format is invalid or password is wrong
            RuntimeError: If decryption fails
        """
        input_path = os.path.abspath(input_path)
        
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")
        
        try:
            # Read encrypted file
            with open(input_path, 'r', encoding='utf-8') as f:
                encrypted_file = json.load(f)
            
            # Validate file format
            if not isinstance(encrypted_file, dict) or 'metadata' not in encrypted_file:
                raise ValueError("Invalid encrypted file format")
            
            metadata = encrypted_file['metadata']
            encrypted_data = encrypted_file['encrypted_data']
            
            # Extract salt and derive key
            salt = base64.b64decode(metadata['salt'])
            key = self._derive_key(password, salt)
            
            # Decrypt data
            fernet = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted_data = fernet.decrypt(encrypted_bytes)
            
            # Convert to string
            decrypted_content = decrypted_data.decode('utf-8')
            
            # Write to output file if specified
            if output_path:
                output_path = os.path.abspath(output_path)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(decrypted_content)
                os.chmod(output_path, 0o600)
                
                self._log_operation("DECRYPT", input_path, True, f"Output: {output_path}")
                logger.info(f"Successfully decrypted {input_path} -> {output_path}")
            else:
                self._log_operation("DECRYPT", input_path, True, "Output: stdout")
            
            return decrypted_content
            
        except Exception as e:
            self._log_operation("DECRYPT", input_path, False, str(e))
            if "InvalidToken" in str(e):
                raise ValueError("Invalid password or corrupted file")
            raise RuntimeError(f"Decryption failed: {e}")
    
    def verify_file(self, file_path: str, password: str) -> bool:
        """
        Verify that an encrypted file can be decrypted with the given password.
        
        Args:
            file_path: Path to the encrypted file
            password: Password to test
            
        Returns:
            True if file can be decrypted, False otherwise
        """
        try:
            self.decrypt_file(file_path, password, output_path=None)
            return True
        except Exception:
            return False
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get metadata about an encrypted file.
        
        Args:
            file_path: Path to the encrypted file
            
        Returns:
            Dictionary with file metadata
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid
        """
        file_path = os.path.abspath(file_path)
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_file = json.load(f)
            
            if not isinstance(encrypted_file, dict) or 'metadata' not in encrypted_file:
                raise ValueError("Invalid encrypted file format")
            
            metadata = encrypted_file['metadata']
            file_stats = os.stat(file_path)
            
            return {
                "file_path": file_path,
                "file_size": file_stats.st_size,
                "modified_time": datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                "encryption_version": metadata.get("version", "unknown"),
                "algorithm": metadata.get("algorithm", "unknown"),
                "kdf": metadata.get("kdf", "unknown"),
                "iterations": metadata.get("iterations", 0),
                "encrypted_at": metadata.get("encrypted_at", "unknown"),
                "original_file": metadata.get("original_file", "unknown")
            }
            
        except json.JSONDecodeError:
            raise ValueError("File is not a valid encrypted configuration file")
    
    def change_password(self, file_path: str, old_password: str, new_password: str) -> None:
        """
        Change the password of an encrypted file.
        
        Args:
            file_path: Path to the encrypted file
            old_password: Current password
            new_password: New password
            
        Raises:
            ValueError: If old password is wrong or new password is too weak
            RuntimeError: If operation fails
        """
        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters long")
        
        try:
            # Decrypt with old password
            decrypted_content = self.decrypt_file(file_path, old_password, output_path=None)
            
            # Create temporary file with decrypted content
            temp_file = file_path + ".tmp.decrypt"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
            
            # Re-encrypt with new password
            self.encrypt_file(temp_file, new_password, output_path=file_path)
            
            # Clean up temporary file
            os.remove(temp_file)
            
            self._log_operation("CHANGE_PASSWORD", file_path, True, "Password changed successfully")
            logger.info(f"Successfully changed password for {file_path}")
            
        except Exception as e:
            # Clean up on failure
            temp_file = file_path + ".tmp.decrypt"
            if os.path.exists(temp_file):
                os.remove(temp_file)
            self._log_operation("CHANGE_PASSWORD", file_path, False, str(e))
            raise RuntimeError(f"Password change failed: {e}")


def get_password_from_env() -> Optional[str]:
    """Get encryption password from TAILOPS_SECRET environment variable."""
    return os.environ.get('TAILOPS_SECRET')


def is_encrypted_file(file_path: str) -> bool:
    """Check if a file is an encrypted tailops configuration file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return isinstance(data, dict) and 'metadata' in data and 'encrypted_data' in data
    except:
        return False
