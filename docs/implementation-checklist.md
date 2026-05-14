# Implementation Checklist

This checklist maps the technical specification to the current repository implementation.

## Implemented In Code

1. Composer package metadata for `globus-studio/fingerprint` with PSR-4 namespace `GlobusStudio\\Fingerprint\\`.
2. PHP 8.3 to PHP 8.5 compatible strict-typed source files.
3. Privacy profiles: `strict`, `balanced`, `maximum`, `custom`.
4. Production secret validation and development hashing mode.
5. HMAC-SHA-256 hasher, optional Sodium hasher, canonical JSON payloads, algorithm and key versioning.
6. Request abstractions for native PHP arrays plus PSR-7, PSR-15, Symfony, Laravel, Laminas, and Slim-style adapters.
7. Header, network, proxy, server, framework, TLS, cookie, and header order collectors.
8. User-Agent, Accept, Accept-Language, Accept-Encoding, Client Hints, IP, CIDR, and canonical JSON normalization.
9. Trusted proxy model with explicit CIDR allowlist and trusted forwarded headers.
10. Full IP excluded from `strict` and `balanced` profiles by default.
11. Authorization, cookie, token, CSRF, API key, and secret-like headers denied by default.
12. Cookie allowlist with presence, hash, and normalized modes.
13. Fingerprint result with ID, version, profile, scores, signals, environment, diagnostics, TTL, expiration, safe export, storage export, and data portability export.
14. Redaction interface and default redactor for safe output.
15. Confidence, entropy, stability, and risk scoring.
16. Fingerprint matcher with exact, partial, distance, changed signal, stable signal, volatile change, and risk reason support.
17. PSR-15-compatible middleware without hard PSR dependency.
18. In-memory storage implementation and storage interface.
19. Diagnostics for unavailable collectors and warnings.
20. PSR-3-compatible logger hook through `FingerprintBuilder::withLogger()`.

## Verified By Tests

1. Header and value normalization.
2. User-Agent derived browser, OS, engine, device, and bot signals.
3. IPv4 and IPv6 prefixing, CIDR matching, IP classification.
4. Stable balanced fingerprints and deterministic golden fixtures.
5. Strict and balanced privacy behavior for full IP exclusion.
6. Explicit maximum-profile full IP inclusion.
7. Optional header order hashing.
8. Authorization, cookie, API key, raw IP, and raw cookie redaction.
9. Trusted proxy and spoofed `X-Forwarded-For` behavior.
10. Cookie hash and normalized modes.
11. TLS protocol, cipher, and client certificate safe handling.
12. TTL, expiration, safe output, storage output, and export output.
13. Custom redactor behavior.
14. Logger behavior for collector failures.
15. PSR-7, PSR-15, Symfony, Laravel, Laminas, and Slim adapter paths.
16. Matcher levels and unknown comparison behavior.
17. In-memory storage behavior.
18. Golden fixtures for Nginx Chrome, Apache Firefox, IIS Edge, Cloudflare Safari, mobile Chrome, curl, and bot client.

## Verified Tooling

1. `composer validate --strict` passes.
2. `composer test` passes.
3. `composer analyse` passes at PHPStan max level.
4. `composer cs` passes.
5. `composer test:coverage` passes with line coverage above the 85% core target.

## Covered By Documentation

1. Privacy and legal cautions.
2. Configuration examples and profiles.
3. Signal dictionary and denied headers.
4. Trusted proxy model.
5. Server notes for Nginx, Apache, IIS, Caddy, LiteSpeed, OpenResty, FrankenPHP, RoadRunner, and Swoole.
6. Limitations for header order, JA3/JA4, Client Hints, CDN rewrites, IP drift, and collision risk.
7. Algorithm versioning policy.
8. Testing workflow.

## Requires External Infrastructure To Prove

1. Real header order behavior across all production SAPI/server combinations.
2. JA3/JA4 values from a trusted reverse proxy, WAF, CDN, or custom infrastructure header.
3. CDN provider CIDR freshness in production.
4. End-to-end behavior through real Nginx, Apache, IIS, Cloudflare, Fastly, Akamai, AWS ALB, RoadRunner, and Swoole deployments.
5. Legal compliance in a specific product and jurisdiction.
6. Production latency under real workload and hardware.