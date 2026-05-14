<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

final class HeaderNormalizer
{
    public static function normalizeHeaderName(string $headerName): string
    {
        return strtolower(str_replace('_', '-', trim($headerName)));
    }

    public static function normalizeValue(string $value): string
    {
        return trim((string) preg_replace('/\s+/', ' ', $value));
    }

    public static function normalizeAccept(string $value): string
    {
        return self::normalizeCommaSeparatedQValues($value, false);
    }

    public static function normalizeCommaSeparatedQValues(string $value, bool $lowercaseTokens = true): string
    {
        $parts = array_filter(array_map('trim', explode(',', $value)), static fn(string $part): bool => $part !== '');
        $normalizedParts = [];

        foreach ($parts as $part) {
            $segments = array_map('trim', explode(';', $part));
            $token = array_shift($segments) ?? '';
            $token = $lowercaseTokens ? strtolower($token) : $token;
            $normalizedSegments = [$token];

            foreach ($segments as $segment) {
                if ($segment === '') {
                    continue;
                }

                if (preg_match('/^q\s*=\s*(.+)$/i', $segment, $matches) === 1) {
                    $normalizedSegments[] = 'q=' . self::normalizeQuality((string) $matches[1]);
                    continue;
                }

                $normalizedSegments[] = strtolower($segment);
            }

            $normalizedParts[] = implode(';', $normalizedSegments);
        }

        return implode(',', $normalizedParts);
    }

    public static function normalizeQuality(string $quality): string
    {
        $quality = trim($quality);

        if (str_starts_with($quality, '.')) {
            $quality = '0' . $quality;
        }

        $numericQuality = max(0.0, min(1.0, (float) $quality));
        $formatted = rtrim(rtrim(sprintf('%.3F', $numericQuality), '0'), '.');

        return $formatted === '' ? '0' : $formatted;
    }
}
