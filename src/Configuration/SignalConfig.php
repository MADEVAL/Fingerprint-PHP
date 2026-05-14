<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Configuration;

final readonly class SignalConfig
{
    public function __construct(
        private int $weight,
        private bool $enabled = true,
    ) {}

    public function weight(): int
    {
        return $this->weight;
    }

    public function enabled(): bool
    {
        return $this->enabled;
    }
}
