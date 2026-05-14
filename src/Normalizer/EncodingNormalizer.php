<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

final class EncodingNormalizer
{
    public function normalize(string $value): string
    {
        return HeaderNormalizer::normalizeCommaSeparatedQValues($value, true);
    }
}
