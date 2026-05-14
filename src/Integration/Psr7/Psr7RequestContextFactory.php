<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Integration\Psr7;

use GlobusStudio\Fingerprint\Request\CookieBag;
use GlobusStudio\Fingerprint\Request\HeaderBag;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Request\ServerBag;

final class Psr7RequestContextFactory
{
    public function fromRequest(object $request): RequestContext
    {
        $headers = $this->stringKeyArray(method_exists($request, 'getHeaders') ? $request->getHeaders() : []);
        $serverParams = $this->stringKeyArray(method_exists($request, 'getServerParams') ? $request->getServerParams() : []);
        $cookies = $this->stringKeyArray(method_exists($request, 'getCookieParams') ? $request->getCookieParams() : []);
        $method = method_exists($request, 'getMethod') ? $this->stringValue($request->getMethod(), 'GET') : $this->stringValue($serverParams['REQUEST_METHOD'] ?? null, 'GET');
        $uri = method_exists($request, 'getUri') ? $this->stringValue($request->getUri(), '/') : $this->stringValue($serverParams['REQUEST_URI'] ?? null, '/');
        $protocol = method_exists($request, 'getProtocolVersion') ? 'HTTP/' . $this->stringValue($request->getProtocolVersion(), '1.1') : $this->stringValue($serverParams['SERVER_PROTOCOL'] ?? null, 'HTTP/1.1');

        return new RequestContext(
            new HeaderBag($headers),
            new ServerBag($serverParams),
            new CookieBag($cookies),
            strtoupper((string) $method),
            $uri,
            $protocol,
            $this->stringValue($serverParams['REMOTE_ADDR'] ?? null),
            PHP_SAPI,
        );
    }

    /** @return array<string, mixed> */
    private function stringKeyArray(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $normalized = [];

        foreach ($value as $key => $item) {
            $normalized[(string) $key] = $item;
        }

        return $normalized;
    }

    private function stringValue(mixed $value, string $default = ''): string
    {
        if ($value === null) {
            return $default;
        }

        if (is_scalar($value) || $value instanceof \Stringable) {
            return (string) $value;
        }

        return $default;
    }
}
