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

## [1.1.0] - 2025-06-02

### Added
- **JSON Output Format**: Added `--json` flag to all major commands for automation and RMM integration
  - `tailops tenant list --json` - JSON output for tenant listing
  - `tailops device list --json` - JSON output for device listing
  - `tailops tenant test --json` - JSON output for connectivity testing
- **OutputFormatter System**: Professional output formatting with auto-detection for piped/redirected output
- **Consistent JSON Schema**: Standardized JSON structure across all commands with timestamps and metadata
- **Auto-Detection**: Automatic JSON format when output is piped or redirected for seamless automation
- **RMM Integration Ready**: Machine-readable output perfect for monitoring and management systems

### Technical
- Added `tailops/utils/formatter.py` with comprehensive output formatting
- Enhanced command structure to support multiple output formats
- Normalized data structures for consistent API responses
- Maintained backward compatibility with existing table output

## [1.2.0] - 2025-06-02

### Added
- **Configuration Encryption**: Enterprise-grade security for sensitive configuration data
  - `tailops secrets encrypt` - Encrypt configuration files with AES-256 encryption
  - `tailops secrets decrypt` - Decrypt configuration files securely
  - `tailops secrets info` - View encryption metadata and file information
  - `tailops secrets verify` - Verify file integrity and password validity
  - `tailops secrets rotate` - Change encryption passwords securely
  - `tailops secrets migrate` - Convert plain text configs to encrypted format
- **PBKDF2 Key Derivation**: Industry-standard password-based encryption with 100,000+ iterations
- **Audit Logging**: Complete audit trail of encryption/decryption operations in `~/.tailops/logs/secrets.log`
- **Multiple Password Sources**: Support for environment variables (`TAILOPS_SECRET`) and interactive prompts
- **Atomic Operations**: Safe file operations with backup creation and rollback capability
- **Password Strength Validation**: Enforced minimum password requirements
- **Secure File Permissions**: Automatic setting of restrictive file permissions (600)

### Security
- **Fernet Encryption**: AES-128 in CBC mode with HMAC-SHA256 for authenticated encryption
- **Salt-based Protection**: Unique salt per file prevents rainbow table attacks
- **Integrity Verification**: Built-in tamper detection and corruption prevention
- **Metadata Protection**: Encrypted files include version info and encryption parameters
- **Secure Cleanup**: Temporary files are properly cleaned up on failure

### Technical
- Added `cryptography>=3.4.8` dependency for encryption functionality
- Enhanced CLI with comprehensive secrets management commands
- Professional error handling with specific security-focused error messages
- Cross-platform compatibility with proper path handling

## [1.3.0] - 2025-06-02

### Added
- **API Key Rotation System**: Complete lifecycle management for Tailscale API keys
  - `tailops key list` - Display API key status and validity for all tenants
  - `tailops key rotate --tenant <name>` - Safely rotate API key for specific tenant
  - `tailops key rotate-all` - Bulk rotation across all tenants with configurable delays
  - `tailops key test` - Validate API key permissions and connectivity
  - `tailops key archive` - Archive old rotation logs for compliance
- **Safe Rotation Workflow**: Enterprise-grade key rotation with rollback capability
- **Audit Logging**: Complete rotation history in `~/.tailops/logs/rotation.log`
- **Dry-Run Mode**: Preview all changes with `--dry-run` flag before execution
- **Batch Processing**: Controlled bulk operations with configurable delays
- **Permission Testing**: Comprehensive API key validation and capability checking

### Security
- **Atomic Operations**: New keys tested before old keys are retired
- **Rollback Safety**: Configuration updates only occur after successful validation
- **Audit Compliance**: Detailed logging of all key rotation activities
- **Zero-Downtime**: Keys remain functional during rotation process
- **Encrypted Config Support**: Seamless integration with encrypted configuration files

### Enterprise Features
- **MSP-Scale Operations**: Bulk rotation across hundreds of client tenants
- **Change Management**: Dry-run capabilities for operational approval workflows
- **Compliance Logging**: Timestamped audit trails for security compliance
- **Automated Scheduling**: Foundation for future automated rotation schedules
- **Progress Tracking**: Real-time feedback during bulk operations

### Technical
- Enhanced Tailscale API client with comprehensive key management endpoints
- Professional error handling with specific rollback procedures
- Integration with existing encryption and configuration systems
- Cross-platform rotation log management and archival

## [Unreleased]

### Planned for v1.4.0
- [ ] Scheduled automatic key rotation with configurable intervals
- [ ] Integration with external secret management systems (Vault, etc.)
- [ ] Additional Tailscale API coverage (ACLs, DNS management)
- [ ] Enhanced notification system for rotation events

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
