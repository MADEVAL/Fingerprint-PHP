# GLOBUS.studio Fingerprint

[![PHP 8.3+](https://img.shields.io/badge/PHP-8.3%2B-777bb4?logo=php&logoColor=white)](https://www.php.net/supported-versions.php)
[![Tests passed](https://img.shields.io/badge/tests-passed-brightgreen)](https://github.com/globus-studio/fingerprint/actions/workflows/ci.yml)
[![Coverage 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](docs/testing.md)

`globus-studio/fingerprint` is a privacy-aware server-side PHP fingerprinting library for security, risk scoring, and probabilistic client identification.

It is designed for PHP 8.3, PHP 8.4, PHP 8.5 and modern deployments behind Nginx, Apache, IIS, CDN, load balancers, RoadRunner, Swoole, and PSR-7 compatible runtimes.

> Fingerprints can be personal or pseudonymous data. Use this package only with a valid legal basis, clear retention policy, and a privacy review appropriate for your product.

## Installation

```bash
composer require globus-studio/fingerprint
```

## Quick Start

```php
<?php

declare(strict_types=1);

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintBuilder;

$config = FingerprintConfig::balanced(
    secret: $_ENV['APP_FINGERPRINT_SECRET']
);

$result = FingerprintBuilder::fromGlobals($config)->build();

echo $result->id();
echo $result->confidence();
```

## Trusted Proxies

```php
$config = FingerprintConfig::balanced($_ENV['APP_FINGERPRINT_SECRET'])
    ->withTrustedProxies(['10.0.0.0/8', '172.16.0.0/12'])
    ->withTrustedHeaders(['x-forwarded-for', 'x-forwarded-proto']);
```

Forwarded headers are ignored unless `REMOTE_ADDR` is a trusted proxy. This prevents trivial `X-Forwarded-For` spoofing.

## Diagnostics Logging

```php
$result = FingerprintBuilder::fromGlobals($config)
    ->withLogger($psrCompatibleLogger)
    ->build();
```

The logger is optional. Without it, diagnostics remain available through `$result->diagnostics()`.

## Matching

```php
$match = $matcher->compare($currentFingerprint, $storedFingerprint);

if ($match->level()->isSuspicious()) {
    // Trigger step-up authentication or manual review.
}
```

## Privacy Modes

- `strict`: minimal signals, no full IP, no raw values.
- `balanced`: recommended default for security use cases.
- `maximum`: explicit high-signal mode, requires a stronger legal basis.
- `custom`: application-defined signal policy.

## Documentation

- [Privacy](docs/privacy.md)
- [Configuration](docs/configuration.md)
- [Signals](docs/signals.md)
- [Trusted proxies](docs/trusted-proxies.md)
- [Limitations](docs/limitations.md)
- [Algorithm versioning](docs/algorithm-versioning.md)
- [Testing](docs/testing.md)
- [Implementation checklist](docs/implementation-checklist.md)
- [Laminas](docs/frameworks/laminas.md)
- [Slim](docs/frameworks/slim.md)

## License

MIT. See [LICENSE](LICENSE).

---

## Important Limits

Server-side fingerprinting is probabilistic. NAT, VPN, corporate proxies, mobile networks, browser privacy protections, CDN rewrites, and browser updates can all change signals. Do not use a fingerprint as the only authentication or blocking factor.