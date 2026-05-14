<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Request;

use DateTimeImmutable;

final readonly class RequestContext
{
    public function __construct(
        private HeaderBag $headers,
        private ServerBag $server,
        private CookieBag $cookies,
        private string $method,
        private string $uri,
        private string $protocol,
        private string $remoteAddress,
        private string $sapi,
        private DateTimeImmutable $receivedAt = new DateTimeImmutable(),
    ) {}

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $cookies
     */
    public static function fromArrays(array $server, array $cookies = []): self
    {
        $serverBag = new ServerBag($server);

        return new self(
            HeaderBag::fromServer($server),
            $serverBag,
            new CookieBag($cookies),
            strtoupper($serverBag->string('REQUEST_METHOD', 'GET')),
            $serverBag->string('REQUEST_URI', '/'),
            $serverBag->string('SERVER_PROTOCOL', 'HTTP/1.1'),
            $serverBag->string('REMOTE_ADDR', ''),
            PHP_SAPI,
        );
    }

    public function headers(): HeaderBag
    {
        return $this->headers;
    }

    public function server(): ServerBag
    {
        return $this->server;
    }

    public function cookies(): CookieBag
    {
        return $this->cookies;
    }

    public function method(): string
    {
        return $this->method;
    }

    public function uri(): string
    {
        return $this->uri;
    }

    public function protocol(): string
    {
        return $this->protocol;
    }

    public function remoteAddress(): string
    {
        return $this->remoteAddress;
    }

    public function sapi(): string
    {
        return $this->sapi;
    }

    public function receivedAt(): DateTimeImmutable
    {
        return $this->receivedAt;
    }
}
