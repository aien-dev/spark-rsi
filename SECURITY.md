# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of sovereign agent infrastructure seriously. If you discover a vulnerability, please report it responsibly rather than opening a public issue.

### Reporting Channels
- Email: aien@aienos.com
- Key: Available upon request or via public keyservers.

### Sovereign Security Invariants
- Zero plaintext API tokens or keys on disk. All integrations must use hardware TPM vault or secure loopback credential injection.
- Loopback isolation: Daemons and internal IPC default strictly to 127.0.0.1.
- Safe deserialization: Untrusted inputs are strictly schema-validated before processing.
