<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Hasher;

final readonly class CanonicalPayload
{
    /** @param array<string, mixed> $payload */
    public function __construct(private array $payload) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->payload;
    }
}
