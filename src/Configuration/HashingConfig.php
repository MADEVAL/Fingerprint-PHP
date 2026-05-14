<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Configuration;

use GlobusStudio\Fingerprint\Exception\ConfigurationException;

final readonly class HashingConfig
{
    public function __construct(
        private string $secret,
        private string $algorithmVersion = 'gsfp-v1',
        private string $keyVersion = 'v1',
        private bool $devMode = false,
        private string $encoding = 'hex',
    ) {
        if ($this->secret === '' && !$this->devMode) {
            throw new ConfigurationException('A non-empty fingerprint secret is required outside development mode.');
        }
    }

    public static function production(string $secret, string $algorithmVersion = 'gsfp-v1', string $keyVersion = 'v1'): self
    {
        return new self($secret, $algorithmVersion, $keyVersion, false);
    }

    public static function development(?string $secret = null): self
    {
        return new self($secret ?? 'dev-secret-change-me', 'gsfp-v1', 'dev', true);
    }

    public function secret(): string
    {
        return $this->secret;
    }

    public function algorithmVersion(): string
    {
        return $this->algorithmVersion;
    }

    public function keyVersion(): string
    {
        return $this->keyVersion;
    }

    public function devMode(): bool
    {
        return $this->devMode;
    }

    public function encoding(): string
    {
        return $this->encoding;
    }
}
