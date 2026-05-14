<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Request;

final readonly class CookieBag
{
    /** @param array<string, mixed> $cookies */
    public function __construct(private array $cookies = []) {}

    public function get(string $name, ?string $default = null): ?string
    {
        $value = $this->cookies[$name] ?? $default;

        return is_scalar($value) || $value === null ? ($value === null ? null : (string) $value) : $default;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->cookies);
    }

    /** @return array<string, mixed> */
    public function all(): array
    {
        return $this->cookies;
    }
}
