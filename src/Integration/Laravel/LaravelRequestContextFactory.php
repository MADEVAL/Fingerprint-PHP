<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Integration\Laravel;

use GlobusStudio\Fingerprint\Integration\Symfony\SymfonyRequestContextFactory;
use GlobusStudio\Fingerprint\Request\RequestContext;

final readonly class LaravelRequestContextFactory
{
    public function __construct(private SymfonyRequestContextFactory $factory = new SymfonyRequestContextFactory()) {}

    public function fromRequest(object $request): RequestContext
    {
        return $this->factory->fromRequest($request);
    }
}
