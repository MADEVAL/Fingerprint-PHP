<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Configuration;

final readonly class IpPrefixingConfig
{
    public function __construct(
        private int $ipv4PrefixLength = 24,
        private int $ipv6PrefixLength = 56,
        private bool $allowFullIpAddress = false,
    ) {}

    public function ipv4PrefixLength(): int
    {
        return $this->ipv4PrefixLength;
    }

    public function ipv6PrefixLength(): int
    {
        return $this->ipv6PrefixLength;
    }

    public function allowFullIpAddress(): bool
    {
        return $this->allowFullIpAddress;
    }
}
