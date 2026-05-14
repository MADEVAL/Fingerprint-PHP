# Slim

Slim applications use PSR-7 request objects. Use `SlimRequestContextFactory` for a Slim-named adapter, or use the generic PSR-7 request factory directly.

```php
use GlobusStudio\Fingerprint\Integration\Slim\SlimRequestContextFactory;

$context = (new SlimRequestContextFactory())->fromRequest($request);
```

Trusted proxy handling must be configured explicitly in the fingerprint configuration.