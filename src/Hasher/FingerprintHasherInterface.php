<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Hasher;

use GlobusStudio\Fingerprint\Configuration\HashingConfig;

interface FingerprintHasherInterface
{
    public function hash(CanonicalPayload $payload, HashingConfig $config): string;
}
