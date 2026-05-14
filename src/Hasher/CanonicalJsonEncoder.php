<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Hasher;

final class CanonicalJsonEncoder
{
    /** @param array<string, mixed> $payload */
    public function encode(array $payload): string
    {
        $sortedPayload = $this->sortRecursively($payload);

        return json_encode($sortedPayload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }

    private function sortRecursively(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (!$this->isList($value)) {
            ksort($value);
        }

        foreach ($value as $key => $item) {
            $value[$key] = $this->sortRecursively($item);
        }

        return $value;
    }

    /** @param array<mixed> $value */
    private function isList(array $value): bool
    {
        return array_keys($value) === range(0, count($value) - 1);
    }
}
