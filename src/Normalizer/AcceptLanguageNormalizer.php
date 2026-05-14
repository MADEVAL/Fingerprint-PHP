<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

final class AcceptLanguageNormalizer
{
    public function normalize(string $value): string
    {
        $parts = array_filter(array_map('trim', explode(',', $value)), static fn(string $part): bool => $part !== '');
        $normalizedParts = [];

        foreach ($parts as $part) {
            $segments = array_map('trim', explode(';', $part));
            $languageTag = $this->normalizeLanguageTag(array_shift($segments) ?? '');
            $normalizedSegments = [$languageTag];

            foreach ($segments as $segment) {
                if (preg_match('/^q\s*=\s*(.+)$/i', $segment, $matches) === 1) {
                    $normalizedSegments[] = 'q=' . HeaderNormalizer::normalizeQuality((string) $matches[1]);
                }
            }

            $normalizedParts[] = implode(';', $normalizedSegments);
        }

        return implode(',', $normalizedParts);
    }

    private function normalizeLanguageTag(string $languageTag): string
    {
        $subtags = explode('-', str_replace('_', '-', trim($languageTag)));

        foreach ($subtags as $index => $subtag) {
            $subtags[$index] = $index === 1 && strlen($subtag) === 2 ? strtoupper($subtag) : strtolower($subtag);
        }

        return implode('-', array_filter($subtags, static fn(string $subtag): bool => $subtag !== ''));
    }
}
