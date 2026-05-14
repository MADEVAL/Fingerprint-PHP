# Laminas

Laminas applications commonly use PSR-7 request objects. Use `LaminasRequestContextFactory` when you want an explicit framework-facing adapter, or use the generic PSR-7 factory directly.

```php
use GlobusStudio\Fingerprint\Integration\Laminas\LaminasRequestContextFactory;

$context = (new LaminasRequestContextFactory())->fromRequest($request);
```

Keep trusted proxy configuration aligned with your Laminas middleware stack.