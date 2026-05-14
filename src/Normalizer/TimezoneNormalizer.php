<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

final class TimezoneNormalizer
{
    public function normalize(string $timezone): string
    {
        return trim($timezone);
    }
}
