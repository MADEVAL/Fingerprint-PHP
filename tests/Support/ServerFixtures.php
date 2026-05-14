<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests\Support;

final class ServerFixtures
{
    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    public static function nginxChrome(array $overrides = []): array
    {
        return array_replace([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/account/security?ignored=true',
            'SERVER_PROTOCOL' => 'HTTP/2',
            'SERVER_SOFTWARE' => 'nginx/1.26.0',
            'GATEWAY_INTERFACE' => 'CGI/1.1',
            'REMOTE_ADDR' => '203.0.113.44',
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'HTTP_HOST' => 'example.com',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9,uk;q=.7',
            'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br, zstd',
            'HTTP_SEC_CH_UA' => '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'HTTP_SEC_CH_UA_MOBILE' => '?0',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Windows"',
            'HTTP_SEC_FETCH_SITE' => 'same-origin',
            'HTTP_SEC_FETCH_MODE' => 'navigate',
            'HTTP_SEC_FETCH_DEST' => 'document',
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    public static function apacheFirefox(array $overrides = []): array
    {
        return array_replace([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/dashboard',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'SERVER_SOFTWARE' => 'Apache/2.4.59',
            'GATEWAY_INTERFACE' => 'CGI/1.1',
            'REMOTE_ADDR' => '198.51.100.77',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
            'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'HTTP_ACCEPT_LANGUAGE' => 'de-DE,de;q=0.8,en-US;q=0.5,en;q=0.3',
            'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br',
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    public static function iisEdge(array $overrides = []): array
    {
        return array_replace([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/orders',
            'SERVER_PROTOCOL' => 'HTTP/2',
            'SERVER_SOFTWARE' => 'Microsoft-IIS/10.0',
            'REMOTE_ADDR' => '192.0.2.25',
            'HTTPS' => 'on',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
            'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'HTTP_ACCEPT_LANGUAGE' => 'en-GB,en;q=0.9',
            'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Windows"',
        ], $overrides);
    }
}
