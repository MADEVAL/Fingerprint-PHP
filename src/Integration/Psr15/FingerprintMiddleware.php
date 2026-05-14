<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Integration\Psr15;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Exception\UnsupportedEnvironmentException;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Integration\Psr7\Psr7RequestContextFactory;

final readonly class FingerprintMiddleware
{
    public function __construct(
        private FingerprintConfig $config,
        private string $attributeName = 'globus_fingerprint',
        private Psr7RequestContextFactory $requestContextFactory = new Psr7RequestContextFactory(),
    ) {}

    public function process(object $request, object $handler): object
    {
        $result = FingerprintBuilder::fromRequestContext($this->requestContextFactory->fromRequest($request), $this->config)->build();

        if (method_exists($request, 'withAttribute')) {
            $request = $request->withAttribute($this->attributeName, $result);
            if (!is_object($request)) {
                throw new UnsupportedEnvironmentException('PSR-7 withAttribute() must return a request object.');
            }
        }

        $callable = [$handler, 'handle'];

        if (!is_callable($callable)) {
            throw new UnsupportedEnvironmentException('PSR-15 handler must expose a handle() method.');
        }

        $response = $callable($request);

        if (!is_object($response)) {
            throw new UnsupportedEnvironmentException('PSR-15 handler must return a response object.');
        }

        return $response;
    }
}
