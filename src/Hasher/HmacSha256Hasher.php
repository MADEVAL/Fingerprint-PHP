<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Hasher;

use GlobusStudio\Fingerprint\Configuration\HashingConfig;

final readonly class HmacSha256Hasher implements FingerprintHasherInterface
{
    public function __construct(private CanonicalJsonEncoder $encoder = new CanonicalJsonEncoder()) {}

    public function hash(CanonicalPayload $payload, HashingConfig $config): string
    {
        $jsonPayload = $this->encoder->encode($payload->toArray());
        $digest = hash_hmac('sha256', $jsonPayload, $config->secret(), true);

        if ($config->encoding() === 'base64url') {
            $encodedDigest = rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
        } else {
            $encodedDigest = bin2hex($digest);
        }

        return str_replace('-', '_', $config->algorithmVersion()) . '_' . $encodedDigest;
    }
}
