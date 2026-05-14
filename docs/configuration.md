# Configuration

```php
use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;

$strict = FingerprintConfig::strict($_ENV['APP_FINGERPRINT_SECRET']);
$balanced = FingerprintConfig::balanced($_ENV['APP_FINGERPRINT_SECRET']);
$maximum = FingerprintConfig::maximum($_ENV['APP_FINGERPRINT_SECRET']);

$custom = FingerprintConfig::custom($_ENV['APP_FINGERPRINT_SECRET'])
    ->withTrustedProxies(['10.0.0.0/8'])
    ->withTrustedHeaders(['x-forwarded-for'])
    ->includeClientHints(true)
    ->includeHeaderOrder(false)
    ->includeCookies(['device_consent' => 'presence']);
```

Production configuration must provide a non-empty secret. Development mode is available only through explicit configuration and should not be used for stored production fingerprints.