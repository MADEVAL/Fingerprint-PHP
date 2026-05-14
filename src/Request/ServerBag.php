<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Request;

final readonly class ServerBag
{
    /** @param array<string, mixed> $server */
    public function __construct(private array $server = []) {}

    public function get(string $name, mixed $default = null): mixed
    {
        return $this->server[$name] ?? $default;
    }

    public function string(string $name, string $default = ''): string
    {
        $value = $this->get($name, $default);

        return is_scalar($value) ? (string) $value : $default;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->server);
    }

    /** @return array<string, mixed> */
    public function all(): array
    {
        return $this->server;
    }
}
