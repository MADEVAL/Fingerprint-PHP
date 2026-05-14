<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Hasher;

use GlobusStudio\Fingerprint\Configuration\HashingConfig;
use GlobusStudio\Fingerprint\Exception\UnsupportedEnvironmentException;

final readonly class SodiumHasher implements FingerprintHasherInterface
{
    public function __construct(private CanonicalJsonEncoder $encoder = new CanonicalJsonEncoder()) {}

    public function hash(CanonicalPayload $payload, HashingConfig $config): string
    {
        if (!function_exists('sodium_crypto_generichash')) {
            throw new UnsupportedEnvironmentException('The sodium extension is required for SodiumHasher.');
        }

        $jsonPayload = $this->encoder->encode($payload->toArray());
        $key = substr(hash('sha256', $config->secret(), true), 0, SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
        $digest = sodium_crypto_generichash($jsonPayload, $key, 32);

        return str_replace('-', '_', $config->algorithmVersion()) . '_' . bin2hex($digest);
    }
}
