<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Request;

final class RequestContextFactory
{
    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $cookies
     */
    public function fromArrays(array $server, array $cookies = []): RequestContext
    {
        return RequestContext::fromArrays($server, $cookies);
    }
}
