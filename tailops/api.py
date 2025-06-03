"""
Tailscale API integration for tailops.
"""

import requests
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class TailscaleAPI:
    """Tailscale API client."""
    
    BASE_URL = "https://api.tailscale.com/api/v2/"
    
    def __init__(self, api_key: str, tailnet: str):
        self.api_key = api_key
        self.tailnet = tailnet
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        })
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request with error handling."""
        url = urljoin(self.BASE_URL, endpoint)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            # Handle empty responses
            if response.status_code == 204 or not response.content:
                return {}
            
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                raise ValueError("Invalid API key or insufficient permissions")
            elif response.status_code == 404:
                raise ValueError(f"Resource not found: {endpoint}")
            elif response.status_code == 429:
                raise ValueError("API rate limit exceeded")
            else:
                logger.error(f"HTTP error {response.status_code}: {response.text}")
                raise RuntimeError(f"API request failed: {e}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {e}")
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices in the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/devices"
        response = self._request('GET', endpoint)
        return response.get('devices', [])
    
    def get_device(self, device_id: str) -> Dict[str, Any]:
        """Get specific device information."""
        endpoint = f"device/{device_id}"
        return self._request('GET', endpoint)
    
    def authorize_device(self, device_id: str) -> Dict[str, Any]:
        """Authorize a device."""
        endpoint = f"device/{device_id}/authorized"
        return self._request('POST', endpoint, json={'authorized': True})
    
    def delete_device(self, device_id: str) -> bool:
        """Delete a device from the tailnet."""
        endpoint = f"device/{device_id}"
        self._request('DELETE', endpoint)
        return True
    
    def get_device_routes(self, device_id: str) -> List[Dict[str, Any]]:
        """Get subnet routes for a device."""
        endpoint = f"device/{device_id}/routes"
        response = self._request('GET', endpoint)
        return response.get('advertisedRoutes', [])
    
    def set_device_routes(self, device_id: str, routes: List[str]) -> Dict[str, Any]:
        """Set subnet routes for a device."""
        endpoint = f"device/{device_id}/routes"
        return self._request('POST', endpoint, json={'routes': routes})
    
    def get_acl(self) -> Dict[str, Any]:
        """Get the tailnet ACL policy."""
        endpoint = f"tailnet/{self.tailnet}/acl"
        return self._request('GET', endpoint)
    
    def update_acl(self, acl_policy: Dict[str, Any]) -> Dict[str, Any]:
        """Update the tailnet ACL policy."""
        endpoint = f"tailnet/{self.tailnet}/acl"
        return self._request('POST', endpoint, json=acl_policy)
    
    def get_dns_nameservers(self) -> List[str]:
        """Get DNS nameservers for the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/dns/nameservers"
        response = self._request('GET', endpoint)
        return response.get('dns', [])
    
    def set_dns_nameservers(self, nameservers: List[str]) -> Dict[str, Any]:
        """Set DNS nameservers for the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/dns/nameservers"
        return self._request('POST', endpoint, json={'dns': nameservers})
    
    def get_dns_preferences(self) -> Dict[str, Any]:
        """Get DNS preferences for the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/dns/preferences"
        return self._request('GET', endpoint)
    
    def set_dns_preferences(self, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Set DNS preferences for the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/dns/preferences"
        return self._request('POST', endpoint, json=preferences)
    
    def get_tailnet_keys(self) -> List[Dict[str, Any]]:
        """Get auth keys for the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/keys"
        response = self._request('GET', endpoint)
        return response.get('keys', [])
    
    def create_auth_key(self, 
                       reusable: bool = False,
                       ephemeral: bool = False,
                       preauthorized: bool = True,
                       description: Optional[str] = None,
                       tags: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create a new auth key."""
        endpoint = f"tailnet/{self.tailnet}/keys"
        
        data = {
            'capabilities': {
                'devices': {
                    'create': {
                        'reusable': reusable,
                        'ephemeral': ephemeral,
                        'preauthorized': preauthorized
                    }
                }
            }
        }
        
        if description:
            data['description'] = description
        
        if tags:
            data['capabilities']['devices']['create']['tags'] = tags
        
        return self._request('POST', endpoint, json=data)
    
    def delete_auth_key(self, key_id: str) -> bool:
        """Delete an auth key."""
        endpoint = f"tailnet/{self.tailnet}/keys/{key_id}"
        self._request('DELETE', endpoint)
        return True
    
    def test_connection(self) -> bool:
        """Test the API connection and credentials."""
        try:
            self.get_devices()
            return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    # API Key Management Methods
    
    def list_api_keys(self) -> List[Dict[str, Any]]:
        """List all API keys for the tailnet."""
        endpoint = f"tailnet/{self.tailnet}/keys"
        response = self._request('GET', endpoint)
        return response.get('keys', [])
    
    def create_api_key(self, description: str = None, expiry_seconds: int = None) -> Dict[str, Any]:
        """
        Create a new API key.
        
        Args:
            description: Optional description for the key
            expiry_seconds: Optional expiry time in seconds from now
            
        Returns:
            Dictionary containing the new key information
        """
        endpoint = f"tailnet/{self.tailnet}/keys"
        data = {
            'capabilities': {
                'devices': {
                    'create': {
                        'reusable': False,
                        'ephemeral': False,
                        'preauthorized': True
                    }
                }
            }
        }
        
        if description:
            data['description'] = description
        if expiry_seconds:
            data['expirySeconds'] = expiry_seconds
        
        return self._request('POST', endpoint, json=data)
    
    def delete_api_key(self, key_id: str) -> bool:
        """
        Delete/expire an API key.
        
        Args:
            key_id: The ID of the key to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            endpoint = f"tailnet/{self.tailnet}/keys/{key_id}"
            self._request('DELETE', endpoint)
            return True
        except Exception:
            return False
    
    def get_api_key_info(self, key_id: str) -> Dict[str, Any]:
        """
        Get information about a specific API key.
        
        Args:
            key_id: The ID of the key
            
        Returns:
            Dictionary containing key information
        """
        endpoint = f"tailnet/{self.tailnet}/keys/{key_id}"
        return self._request('GET', endpoint)
    
    def test_api_key_permissions(self, test_key: str = None) -> Dict[str, Any]:
        """
        Test API key permissions and connectivity.
        
        Args:
            test_key: Optional key to test (defaults to current key)
            
        Returns:
            Dictionary with test results
        """
        from datetime import datetime
        
        original_key = None
        if test_key:
            original_key = self.api_key
            self.api_key = test_key
            # Update session headers
            self.session.headers.update({
                'Authorization': f'Bearer {test_key}'
            })
        
        try:
            # Test basic connectivity
            devices = self.get_devices()
            keys = self.get_tailnet_keys()
            
            result = {
                'valid': True,
                'can_list_devices': True,
                'can_manage_keys': True,
                'device_count': len(devices),
                'key_count': len(keys),
                'tested_at': datetime.utcnow().isoformat() + 'Z'
            }
            
        except Exception as e:
            result = {
                'valid': False,
                'error': str(e),
                'can_list_devices': False,
                'can_manage_keys': False,
                'tested_at': datetime.utcnow().isoformat() + 'Z'
            }
        
        finally:
            if original_key:
                self.api_key = original_key
                # Restore original headers
                self.session.headers.update({
                    'Authorization': f'Bearer {original_key}'
                })
        
        return result
