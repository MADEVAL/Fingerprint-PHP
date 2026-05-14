<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

final class UserAgentNormalizer
{
    /** @return array<string, string|int> */
    public function profile(string $userAgent): array
    {
        $normalizedUserAgent = HeaderNormalizer::normalizeValue($userAgent);

        return [
            'browser.family' => $this->browserFamily($normalizedUserAgent),
            'browser.major' => $this->majorVersion($normalizedUserAgent),
            'browser.engine' => $this->engine($normalizedUserAgent),
            'os.family' => $this->osFamily($normalizedUserAgent),
            'os.major' => $this->osMajor($normalizedUserAgent),
            'device.class' => $this->deviceClass($normalizedUserAgent),
            'bot.likelihood' => $this->botLikelihood($normalizedUserAgent),
        ];
    }

    public function normalize(string $userAgent): string
    {
        return HeaderNormalizer::normalizeValue($userAgent);
    }

    private function browserFamily(string $userAgent): string
    {
        return match (true) {
            preg_match('/Edg\/(\d+)/i', $userAgent) === 1 => 'Edge',
            preg_match('/OPR\/(\d+)|Opera/i', $userAgent) === 1 => 'Opera',
            preg_match('/Firefox\/(\d+)/i', $userAgent) === 1 => 'Firefox',
            preg_match('/Chrome\/(\d+)/i', $userAgent) === 1 && !str_contains($userAgent, 'Chromium') => 'Chrome',
            preg_match('/Version\/(\d+).*Safari\//i', $userAgent) === 1 => 'Safari',
            preg_match('/curl\//i', $userAgent) === 1 => 'curl',
            preg_match('/wget\//i', $userAgent) === 1 => 'wget',
            preg_match('/python-requests|httpx|guzzle|go-http-client|okhttp/i', $userAgent) === 1 => 'HTTP Library',
            preg_match('/bot|crawler|spider|slurp/i', $userAgent) === 1 => 'Bot',
            default => 'Unknown',
        };
    }

    private function majorVersion(string $userAgent): string
    {
        foreach (['Edg', 'OPR', 'Firefox', 'Chrome', 'Version', 'curl', 'Wget'] as $token) {
            if (preg_match('/' . preg_quote($token, '/') . '\/(\d+)/i', $userAgent, $matches) === 1) {
                return (string) $matches[1];
            }
        }

        return '0';
    }

    private function engine(string $userAgent): string
    {
        return match (true) {
            str_contains($userAgent, 'Gecko/') && str_contains($userAgent, 'Firefox/') => 'Gecko',
            str_contains($userAgent, 'AppleWebKit/') && str_contains($userAgent, 'Chrome/') => 'Blink',
            str_contains($userAgent, 'AppleWebKit/') && str_contains($userAgent, 'Safari/') => 'WebKit',
            default => 'Unknown',
        };
    }

    private function osFamily(string $userAgent): string
    {
        return match (true) {
            preg_match('/Windows NT/i', $userAgent) === 1 => 'Windows',
            preg_match('/Android/i', $userAgent) === 1 => 'Android',
            preg_match('/iPhone|iPad|iPod/i', $userAgent) === 1 => 'iOS',
            preg_match('/Mac OS X|Macintosh/i', $userAgent) === 1 => 'macOS',
            preg_match('/Linux/i', $userAgent) === 1 => 'Linux',
            default => 'Unknown',
        };
    }

    private function osMajor(string $userAgent): string
    {
        if (preg_match('/Windows NT (\d+)/i', $userAgent, $matches) === 1) {
            return (string) $matches[1];
        }

        if (preg_match('/(?:Android|CPU(?: iPhone)? OS|Mac OS X)\s+([\d_\.]+)/i', $userAgent, $matches) === 1) {
            return strtok(str_replace('_', '.', (string) $matches[1]), '.') ?: '0';
        }

        return '0';
    }

    private function deviceClass(string $userAgent): string
    {
        return match (true) {
            preg_match('/bot|crawler|spider|slurp/i', $userAgent) === 1 => 'bot',
            preg_match('/iPad|Tablet/i', $userAgent) === 1 => 'tablet',
            preg_match('/Mobile|Android|iPhone|iPod/i', $userAgent) === 1 => 'mobile',
            preg_match('/SmartTV|TV/i', $userAgent) === 1 => 'tv',
            preg_match('/PlayStation|Xbox|Nintendo/i', $userAgent) === 1 => 'console',
            default => 'desktop',
        };
    }

    private function botLikelihood(string $userAgent): int
    {
        return match (true) {
            preg_match('/bot|crawler|spider|slurp/i', $userAgent) === 1 => 90,
            preg_match('/curl|wget|python-requests|httpx|guzzle|go-http-client|okhttp/i', $userAgent) === 1 => 80,
            $userAgent === '' => 70,
            default => 5,
        };
    }
}
