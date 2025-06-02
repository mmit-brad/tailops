# Changelog

All notable changes to tailops will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-02

### Added
- **Multi-tenant Tailscale management**: Complete CLI toolkit for MSPs
- **Tenant management commands**: Add, remove, list, and test client configurations
- **Device management commands**: List, authorize, remove devices across all tenants
- **Subnet route management**: Configure and manage device routes
- **Professional CLI experience**: Colored output, formatted tables, interactive prompts
- **Comprehensive configuration system**: YAML-based with multiple search paths
- **Enterprise security features**: Secure credential management and validation
- **Cross-tenant operations**: Search and manage resources across all client networks
- **Integration capabilities**: JSON output support for automation
- **Complete Tailscale API v2 integration**: Full API coverage for device operations
- **Error handling and logging**: Comprehensive error messages and debug mode
- **Interactive tenant setup**: Guided onboarding with API validation

### Features
- Multi-tenant architecture with tenant isolation
- Unified device discovery across all client networks
- Advanced filtering by tenant, status, OS, and custom criteria
- Streamlined device authorization workflows
- Complete device lifecycle management
- Audit trail and comprehensive logging
- Professional table displays and progress indicators
- Scriptable commands for automation workflows
- RMM tool integration capabilities

### Documentation
- Comprehensive README with MSP workflows
- Complete command reference
- Security best practices guide
- Installation and configuration documentation
- Real-world usage examples
- Troubleshooting guide

### Technical
- Python 3.8+ compatibility
- Modern packaging with pyproject.toml
- Development tooling configuration (black, flake8, mypy, pytest)
- Proper entry point for `tailops` command
- Package data inclusion for config templates
- CI/CD ready configuration

## [Unreleased]

### Planned for v1.1.0
- [ ] PyPI package distribution
- [ ] JSON output format for all commands
- [ ] Configuration file encryption
- [ ] Automated API key rotation
- [ ] Additional Tailscale API coverage (ACLs, DNS)

### Planned for v1.2.0
- [ ] Web-based dashboard (read-only)
- [ ] Advanced reporting and analytics
- [ ] Webhook integration
- [ ] Multi-user access controls

### Enterprise Features (v2.0.0)
- [ ] SAML/SSO integration
- [ ] Role-based access control
- [ ] Compliance reporting
- [ ] Custom branding options
