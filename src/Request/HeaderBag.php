<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Request;

use GlobusStudio\Fingerprint\Normalizer\HeaderNormalizer;

final class HeaderBag
{
    /** @var array<string, string> */
    private array $headers = [];

    /** @var list<string> */
    private array $order = [];

    /** @param array<string, mixed> $headers */
    public function __construct(array $headers = [])
    {
        foreach ($headers as $name => $value) {
            $this->set((string) $name, $value);
        }
    }

    /** @param array<string, mixed> $server */
    public static function fromServer(array $server): self
    {
        $headers = [];

        foreach ($server as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                $headerName = str_replace('_', '-', substr($name, 5));
                $headers[$headerName] = $value;
                continue;
            }

            if (in_array($name, ['CONTENT_TYPE', 'CONTENT_LENGTH', 'CONTENT_MD5'], true)) {
                $headers[str_replace('_', '-', $name)] = $value;
            }
        }

        return new self($headers);
    }

    public function set(string $name, mixed $value): void
    {
        $normalizedName = HeaderNormalizer::normalizeHeaderName($name);
        $normalizedValue = $this->stringify($value);

        if (isset($this->headers[$normalizedName])) {
            $this->headers[$normalizedName] .= ', ' . $normalizedValue;
            return;
        }

        $this->headers[$normalizedName] = $normalizedValue;
        $this->order[] = $normalizedName;
    }

    public function get(string $name, ?string $default = null): ?string
    {
        return $this->headers[HeaderNormalizer::normalizeHeaderName($name)] ?? $default;
    }

    public function has(string $name): bool
    {
        return array_key_exists(HeaderNormalizer::normalizeHeaderName($name), $this->headers);
    }

    /** @return array<string, string> */
    public function all(): array
    {
        return $this->headers;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->headers);
    }

    /** @return list<string> */
    public function order(): array
    {
        return $this->order;
    }

    private function stringify(mixed $value): string
    {
        if (is_array($value)) {
            return implode(', ', array_map(static fn(mixed $item): string => is_scalar($item) || $item instanceof \Stringable ? (string) $item : '', $value));
        }

        return is_scalar($value) || $value instanceof \Stringable ? (string) $value : '';
    }
}
