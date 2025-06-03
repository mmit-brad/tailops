"""
Output formatting utilities for tailops CLI.
Supports multiple output formats: table, json, with auto-detection for automation.
"""

import json
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional
from .output import print_table, dim


class OutputFormatter:
    """Handles output formatting for different contexts (human vs machine)."""
    
    def __init__(self, format_type: str = "table", auto_detect: bool = True):
        """
        Initialize the output formatter.
        
        Args:
            format_type: Output format ('table', 'json')
            auto_detect: Auto-detect format based on stdout context
        """
        # Auto-detect JSON format if output is redirected/piped
        if auto_detect and not sys.stdout.isatty():
            format_type = "json"
        
        self.format_type = format_type.lower()
        self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def output_tenants(self, tenants_data: List[Dict[str, Any]], command: str = "tenant list") -> None:
        """Format and output tenant data."""
        if self.format_type == "json":
            self._output_json({
                "command": command,
                "timestamp": self.timestamp,
                "total_count": len(tenants_data),
                "data": tenants_data
            })
        else:
            if not tenants_data:
                dim("No tenants configured")
                return
            
            headers = ['Name', 'Tailnet', 'Status', 'Description']
            rows = []
            for tenant in tenants_data:
                rows.append([
                    tenant.get('name', ''),
                    tenant.get('tailnet', ''),
                    tenant.get('status', ''),
                    tenant.get('description', '')
                ])
            print_table(headers, rows)
    
    def output_devices(self, devices_data: List[Dict[str, Any]], command: str = "device list") -> None:
        """Format and output device data."""
        if self.format_type == "json":
            self._output_json({
                "command": command,
                "timestamp": self.timestamp,
                "total_count": len(devices_data),
                "data": devices_data
            })
        else:
            if not devices_data:
                dim("No devices found")
                return
            
            headers = ['Tenant', 'Device Name', 'IP Address', 'Status', 'OS', 'Last Seen']
            rows = []
            for device in devices_data:
                rows.append([
                    device.get('tenant', ''),
                    device.get('name', ''),
                    device.get('ip_addresses', ''),
                    device.get('status', ''),
                    device.get('os', ''),
                    device.get('last_seen', '')
                ])
            print_table(headers, rows)
    
    def output_device_detail(self, device_data: Dict[str, Any], command: str = "device show") -> None:
        """Format and output detailed device information."""
        if self.format_type == "json":
            self._output_json({
                "command": command,
                "timestamp": self.timestamp,
                "data": device_data
            })
        else:
            # Keep existing detailed output format for table mode
            from .output import info
            info(f"Device: {device_data.get('name', 'Unknown')}")
            for key, value in device_data.items():
                if key != 'name':
                    print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def output_tenant_detail(self, tenant_data: Dict[str, Any], command: str = "tenant show") -> None:
        """Format and output detailed tenant information."""
        if self.format_type == "json":
            self._output_json({
                "command": command,
                "timestamp": self.timestamp,
                "data": tenant_data
            })
        else:
            # Keep existing detailed output format for table mode
            from .output import info
            info(f"Tenant: {tenant_data.get('name', 'Unknown')}")
            for key, value in tenant_data.items():
                if key != 'name':
                    print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def output_test_results(self, test_data: List[Dict[str, Any]], command: str = "tenant test") -> None:
        """Format and output tenant test results."""
        if self.format_type == "json":
            self._output_json({
                "command": command,
                "timestamp": self.timestamp,
                "total_count": len(test_data),
                "data": test_data
            })
        else:
            if not test_data:
                dim("No test results")
                return
            
            headers = ['Tenant', 'Status', 'Devices', 'Message']
            rows = []
            for result in test_data:
                rows.append([
                    result.get('tenant', ''),
                    result.get('status', ''),
                    result.get('device_count', ''),
                    result.get('message', '')
                ])
            print_table(headers, rows)
    
    def output_routes(self, routes_data: List[Dict[str, Any]], command: str = "device routes") -> None:
        """Format and output device route information."""
        if self.format_type == "json":
            self._output_json({
                "command": command,
                "timestamp": self.timestamp,
                "total_count": len(routes_data),
                "data": routes_data
            })
        else:
            if not routes_data:
                dim("No routes configured")
                return
            
            headers = ['Route', 'Enabled', 'Approved']
            rows = []
            for route in routes_data:
                rows.append([
                    route.get('route', ''),
                    "✓" if route.get('enabled', False) else "✗",
                    "✓" if route.get('approved', False) else "✗"
                ])
            print_table(headers, rows)
    
    def _output_json(self, data: Dict[str, Any]) -> None:
        """Output data in JSON format."""
        print(json.dumps(data, indent=2, ensure_ascii=False))
    
    @staticmethod
    def normalize_device_data(tenant_name: str, device: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize device data for consistent output."""
        from datetime import datetime
        
        # Parse last seen timestamp
        last_seen = device.get('lastSeen', '')
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                last_seen_str = dt.strftime('%Y-%m-%d %H:%M')
            except:
                last_seen_str = last_seen
        else:
            last_seen_str = 'Never'
        
        return {
            "tenant": tenant_name,
            "name": device.get('name', 'Unknown'),
            "id": device.get('id', ''),
            "ip_addresses": device.get('addresses', []),
            "ip_address_display": ', '.join(device.get('addresses', [])),
            "status": "online" if device.get('online', False) else "offline",
            "os": device.get('os', 'Unknown'),
            "hostname": device.get('hostname', ''),
            "user": device.get('user', ''),
            "authorized": device.get('authorized', False),
            "key_expiry_disabled": device.get('keyExpiryDisabled', False),
            "last_seen": last_seen,
            "last_seen_display": last_seen_str,
            "tags": device.get('tags', [])
        }
    
    @staticmethod
    def normalize_tenant_data(tenant_name: str, tenant_config: Dict[str, Any], status: str = "unknown") -> Dict[str, Any]:
        """Normalize tenant data for consistent output."""
        return {
            "name": tenant_name,
            "display_name": tenant_config.get('name', tenant_name),
            "tailnet": tenant_config.get('tailnet', 'unknown'),
            "description": tenant_config.get('description', ''),
            "status": status,
            "settings": tenant_config.get('settings', {})
        }
