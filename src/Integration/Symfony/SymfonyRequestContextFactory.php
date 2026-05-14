<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Integration\Symfony;

use GlobusStudio\Fingerprint\Request\CookieBag;
use GlobusStudio\Fingerprint\Request\HeaderBag;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Request\ServerBag;

final class SymfonyRequestContextFactory
{
    public function fromRequest(object $request): RequestContext
    {
        $headers = $this->bagArray($this->publicProperty($request, 'headers'));
        $server = $this->bagArray($this->publicProperty($request, 'server'));
        $cookies = $this->bagArray($this->publicProperty($request, 'cookies'));
        $method = method_exists($request, 'getMethod') ? $this->stringValue($request->getMethod(), 'GET') : $this->stringValue($server['REQUEST_METHOD'] ?? null, 'GET');
        $uri = method_exists($request, 'getRequestUri') ? $this->stringValue($request->getRequestUri(), '/') : $this->stringValue($server['REQUEST_URI'] ?? null, '/');
        $clientIp = method_exists($request, 'getClientIp') ? $this->stringValue($request->getClientIp()) : $this->stringValue($server['REMOTE_ADDR'] ?? null);

        return new RequestContext(new HeaderBag($headers), new ServerBag($server), new CookieBag($cookies), strtoupper($method), $uri, $this->stringValue($server['SERVER_PROTOCOL'] ?? null, 'HTTP/1.1'), $clientIp, PHP_SAPI);
    }

    private function publicProperty(object $request, string $name): mixed
    {
        $properties = get_object_vars($request);

        return $properties[$name] ?? null;
    }

    /** @return array<string, mixed> */
    private function bagArray(mixed $bag): array
    {
        if (!is_object($bag) || !method_exists($bag, 'all')) {
            return [];
        }

        $value = $bag->all();

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
