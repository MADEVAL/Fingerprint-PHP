<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Integration\Slim;

use GlobusStudio\Fingerprint\Integration\Psr7\Psr7RequestContextFactory;
use GlobusStudio\Fingerprint\Request\RequestContext;

final readonly class SlimRequestContextFactory
{
    public function __construct(private Psr7RequestContextFactory $factory = new Psr7RequestContextFactory()) {}

    public function fromRequest(object $request): RequestContext
    {
        return $this->factory->fromRequest($request);
    }
}
