<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Request\RequestContext;

final readonly class Fingerprint
{
    public function __construct(private FingerprintConfig $config) {}

    public function fromGlobals(): FingerprintResult
    {
        return FingerprintBuilder::fromGlobals($this->config)->build();
    }

    public function fromRequestContext(RequestContext $request): FingerprintResult
    {
        return FingerprintBuilder::fromRequestContext($request, $this->config)->build();
    }
}
