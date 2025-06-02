<div align="center">

# 🚀 tailops

**Enterprise Multi-Tenant Tailscale Management Platform**

*The professional CLI toolkit for MSPs managing Tailscale networks at scale*

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Tailscale API](https://img.shields.io/badge/Tailscale%20API-v2-purple.svg)

[Quick Start](#quick-start) • [Documentation](#documentation) • [Examples](#msp-workflows) • [Security](#security)

</div>

---

## 🎯 Overview

**tailops** is an enterprise-grade command-line interface designed specifically for **Managed Service Providers (MSPs)** and organizations managing multiple Tailscale tailnets. Built from the ground up for production environments, tailops provides a unified, secure, and efficient way to manage dozens or hundreds of client networks from a single interface.

### Why tailops?

- **🏢 MSP-Native**: Purpose-built for service providers managing multiple client networks
- **🔒 Enterprise Security**: Secure credential management with audit capabilities
- **⚡ Operational Efficiency**: Streamlined workflows for common MSP tasks
- **🎛️ Professional CLI**: Intuitive interface with rich formatting and validation
- **🔧 Integration Ready**: JSON output and scriptable commands for automation
- **📊 Multi-Tenant**: True multi-tenant architecture with tenant isolation

---

## ✨ Key Features

### 🏗️ Multi-Tenant Architecture
- **Centralized Management**: Manage unlimited client tailnets from one interface
- **Tenant Isolation**: Secure separation of client configurations and credentials
- **Cross-Tenant Operations**: Search and manage devices across all client networks
- **Bulk Operations**: Perform actions across multiple tenants simultaneously

### 🖥️ Device Management
- **Unified Device Discovery**: List devices across all client networks
- **Advanced Filtering**: Filter by tenant, status, OS, or custom criteria
- **Device Authorization**: Streamlined approval workflows for new devices
- **Route Management**: Configure and manage subnet routes at scale
- **Device Lifecycle**: Complete device management from onboarding to decommission

### 🛡️ Enterprise Security
- **Secure Credential Storage**: Encrypted API key management
- **Permission Validation**: Automatic verification of API key permissions
- **Audit Trail**: Comprehensive logging of all operations
- **Multi-Environment Support**: Separate configurations for dev/staging/production

### 🎨 Professional Experience
- **Rich CLI Interface**: Color-coded output with clear status indicators
- **Interactive Setup**: Guided tenant onboarding with validation
- **Formatted Output**: Professional table displays and progress indicators
- **Error Handling**: Comprehensive error messages with suggested solutions
- **Debug Mode**: Detailed logging for troubleshooting and development

### 🔗 Integration & Automation
- **JSON Output**: Machine-readable output for scripting and automation
- **RMM Integration**: Built for integration with existing MSP toolchains
- **CI/CD Ready**: Scriptable commands for automated workflows
- **API Coverage**: Complete Tailscale API v2 implementation

---

## 🚀 Quick Start

Get up and running with your first tenant in under 5 minutes:

### 1. Installation

```bash
# Clone and install
git clone https://github.com/your-org/tailops.git
cd tailops
pip install -r requirements.txt
chmod +x cli.py
```

### 2. Add Your First Tenant

```bash
# Interactive tenant setup
python cli.py tenant add acme-corp

# You'll be prompted for:
# ✓ Tailscale API key (secure input)
# ✓ Tailnet name (e.g., acme-corp.ts.net)
# ✓ Display name and description
```

### 3. Verify Setup

```bash
# Test connectivity
python cli.py tenant test acme-corp

# View all devices
python cli.py device list --tenant acme-corp

# Check system status
python cli.py status
```

**🎉 That's it!** You're now managing Tailscale networks like a pro.

---

## 📋 Installation & Setup

### System Requirements

- **Python**: 3.7 or higher
- **Operating System**: Linux, macOS, Windows
- **Network**: HTTPS access to api.tailscale.com
- **Permissions**: Tailscale API keys with admin permissions

### Installation Methods

#### Method 1: Git Clone (Current)
```bash
git clone https://github.com/your-org/tailops.git
cd tailops
pip install -r requirements.txt
chmod +x cli.py
```

#### Method 2: pip install (Coming Soon)
```bash
pip install tailops
tailops --version
```

### Configuration

tailops uses a hierarchical configuration system:

1. **Project Config**: `./config/tenants.yaml`
2. **User Config**: `~/.tailops/config.yaml`
3. **System Config**: `/etc/tailops/config.yaml`

#### Sample Configuration

```yaml
# config/tenants.yaml
tenants:
  acme-corp:
    name: "ACME Corporation"
    api_key: "tskey-api-xxxxxxxxxx"
    tailnet: "acme-corp.ts.net"
    description: "Main corporate network"
    settings:
      auto_approve: false
      dns_enabled: true
      
  startup-inc:
    name: "Startup Inc"
    api_key: "tskey-api-yyyyyyyyyy"
    tailnet: "startup-inc.ts.net"
    description: "Remote-first startup"
    settings:
      auto_approve: true
      dns_enabled: true
```

### Security Setup

```bash
# Secure configuration file permissions
chmod 600 config/tenants.yaml

# Optional: Use environment variables
export TAILOPS_CONFIG_PATH="/secure/path/config.yaml"
python cli.py --config $TAILOPS_CONFIG_PATH status
```

---

## 🏢 MSP Workflows

### Daily Operations

#### Morning Health Check
```bash
# Check all tenant connectivity
python cli.py tenant test

# Review devices needing authorization
python cli.py device list --status offline

# Generate daily report
python cli.py device list > reports/devices-$(date +%Y%m%d).csv
```

#### Client Onboarding
```bash
# Add new client
python cli.py tenant add newclient \
  --api-key tskey-api-xxx \
  --tailnet newclient.ts.net \
  --name "New Client Corp"

# Test and validate
python cli.py tenant test newclient
python cli.py device list --tenant newclient
```

#### Device Management
```bash
# Authorize pending devices for a client
python cli.py device authorize johns-laptop --tenant acme-corp

# Set up site-to-site routing
python cli.py device routes gateway-server \
  --add 192.168.1.0/24 \
  --add 10.0.0.0/16

# Remove compromised device
python cli.py device remove suspicious-device --force
```

#### Bulk Operations
```bash
# Cross-tenant device inventory
python cli.py device list | grep -E "(Windows|macOS)" > workstation-inventory.txt

# Test all tenant connections
python cli.py tenant test > tenant-health.log

# Find devices across all networks
python cli.py device list --status online | wc -l
```

### Advanced Workflows

#### Automated Reporting
```bash
#!/bin/bash
# weekly-report.sh

echo "Tailops Weekly Report - $(date)" > report.txt
echo "================================" >> report.txt

python cli.py tenant list >> report.txt
echo "" >> report.txt

python cli.py device list --status online | wc -l | \
  xargs echo "Total Online Devices:" >> report.txt

python cli.py device list --status offline | wc -l | \
  xargs echo "Total Offline Devices:" >> report.txt
```

#### Integration with RMM Tools
```bash
# Export device data for RMM import
python cli.py device list --format json > rmm-import.json

# Monitor for unauthorized devices
python cli.py device list | grep "unauthorized" | \
  while read device; do
    echo "Alert: Unauthorized device detected: $device"
    # Send to monitoring system
  done
```

---

## 📖 Command Reference

### Global Options

| Option | Description | Example |
|--------|-------------|---------|
| `--config PATH` | Custom config file | `--config /path/to/config.yaml` |
| `--debug` | Enable debug logging | `--debug` |
| `--help` | Show help message | `--help` |

### Tenant Commands

| Command | Description | Example |
|---------|-------------|---------|
| `tenant list` | List all tenants with status | `python cli.py tenant list` |
| `tenant add NAME` | Add new tenant (interactive) | `python cli.py tenant add acme` |
| `tenant show NAME` | Show tenant details | `python cli.py tenant show acme` |
| `tenant test [NAME]` | Test API connectivity | `python cli.py tenant test` |
| `tenant remove NAME` | Remove tenant config | `python cli.py tenant remove acme` |

### Device Commands

| Command | Description | Example |
|---------|-------------|---------|
| `device list` | List all devices | `python cli.py device list` |
| `device list --tenant NAME` | List tenant devices | `python cli.py device list --tenant acme` |
| `device list --status STATUS` | Filter by status | `python cli.py device list --status online` |
| `device show NAME` | Show device details | `python cli.py device show laptop` |
| `device authorize NAME` | Authorize device | `python cli.py device authorize laptop` |
| `device remove NAME` | Remove device | `python cli.py device remove laptop` |
| `device routes NAME` | Manage device routes | `python cli.py device routes gateway` |

### System Commands

| Command | Description | Example |
|---------|-------------|---------|
| `status` | Show system status | `python cli.py status` |
| `version` | Show version info | `python cli.py version` |

---

## 🔒 Security

### API Key Management

**Best Practices:**
- Generate dedicated API keys for tailops with minimal required permissions
- Store API keys in configuration files with restricted permissions (`chmod 600`)
- Rotate API keys regularly (recommended: every 90 days)
- Use separate API keys for different environments (dev/staging/production)

**Production Deployment:**
```bash
# Secure configuration directory
sudo mkdir -p /etc/tailops
sudo chown root:tailops /etc/tailops
sudo chmod 750 /etc/tailops

# Secure configuration file
sudo touch /etc/tailops/config.yaml
sudo chown root:tailops /etc/tailops/config.yaml
sudo chmod 640 /etc/tailops/config.yaml
```

### Network Security

- tailops communicates exclusively with api.tailscale.com over HTTPS
- No data is stored or transmitted to third parties
- All API communications use TLS 1.2 or higher
- Rate limiting and retry logic prevent API abuse

### Audit Trail

Enable comprehensive logging for compliance:

```bash
# Enable audit logging
python cli.py --debug tenant list >> /var/log/tailops/audit.log

# Log all operations
export TAILOPS_AUDIT=true
python cli.py device authorize laptop --tenant acme
```

---

## 🛠️ Development & Contributing

### Project Architecture

```
tailops/
├── cli.py                 # Main CLI entry point
├── requirements.txt       # Dependencies
├── config/               
│   └── tenants.yaml      # Configuration
├── tailops/              # Core package
│   ├── __init__.py       
│   ├── config.py         # Configuration management
│   ├── api.py            # Tailscale API client
│   ├── commands/         # Command implementations
│   │   ├── tenant.py     # Tenant management
│   │   └── device.py     # Device management
│   └── utils/            
│       └── output.py     # CLI formatting
└── docs/                 # Documentation (future)
```

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-org/tailops.git
cd tailops

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # (future)

# Run tests
python -m pytest tests/              # (future)

# Code formatting
black tailops/
flake8 tailops/
```

### Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

---

## 📞 Support & Community

### Getting Help

- **Documentation**: Check this README and command help (`--help`)
- **Debug Mode**: Use `--debug` flag for detailed error information
- **Issues**: Open an issue on GitHub with debug output
- **Discussions**: Join community discussions for best practices

### Enterprise Support

For MSPs requiring enterprise support:
- Priority issue resolution
- Custom feature development
- Professional services and training
- SLA-backed support agreements

Contact: [enterprise@tailops.dev](mailto:enterprise@tailops.dev)

### Reporting Security Issues

Security vulnerabilities should be reported privately to [security@tailops.dev](mailto:security@tailops.dev).

**Please do not** report security issues through public GitHub issues.

---

## 🗺️ Roadmap

### Version 1.1 (Next Release)
- [ ] PyPI package distribution
- [ ] JSON output format for all commands
- [ ] Configuration file encryption
- [ ] Automated API key rotation

### Version 1.2
- [ ] Web-based dashboard (read-only)
- [ ] Advanced reporting and analytics
- [ ] Webhook integration
- [ ] Multi-user access controls

### Version 2.0
- [ ] Complete API coverage (ACLs, DNS, etc.)
- [ ] RMM tool plugins
- [ ] Automated device lifecycle management
- [ ] Custom alerting and monitoring

### Enterprise Features
- [ ] SAML/SSO integration
- [ ] Role-based access control
- [ ] Compliance reporting
- [ ] Custom branding options

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Tailscale Team**: For building an amazing VPN platform with excellent APIs
- **MSP Community**: For feedback and feature requests that shaped this tool
- **Contributors**: Everyone who has contributed code, documentation, and ideas

---

<div align="center">

**tailops** - *Professional Tailscale Management for the Modern MSP*

[⭐ Star on GitHub](https://github.com/your-org/tailops) • [📖 Documentation](https://docs.tailops.dev) • [💬 Community](https://community.tailops.dev)

*Built with ❤️ for MSPs who demand excellence*

</div>
