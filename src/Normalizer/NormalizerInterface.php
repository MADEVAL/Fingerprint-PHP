<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

interface NormalizerInterface
{
    public function normalize(mixed $value, mixed $context = null): mixed;
}
