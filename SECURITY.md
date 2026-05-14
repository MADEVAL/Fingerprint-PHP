# Security Policy

## Supported Versions

Security fixes are provided for the latest stable major version.

## Reporting a Vulnerability

Report vulnerabilities privately to GLOBUS.studio maintainers. Do not open public issues for secrets exposure, fingerprint bypasses, or trust proxy vulnerabilities.

## Security Principles

- Authorization, cookies, CSRF tokens, API keys, and request bodies are excluded from fingerprints by default.
- Forwarded headers are trusted only when the direct peer is configured as a trusted proxy.
- Raw sensitive values are not present in safe exports.
- Production hashing requires an application secret.