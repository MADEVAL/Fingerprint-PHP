<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Integration\Psr7\Psr7RequestContextFactory;
use PHPUnit\Framework\TestCase;

final class IntegrationFactoryTest extends TestCase
{
    public function testPsr7LikeRequestCanBeConvertedWithoutHardDependency(): void
    {
        $request = new class {
            /** @return array<string, list<string>> */
            public function getHeaders(): array
            {
                return ['User-Agent' => ['curl/8.0'], 'Accept' => ['*/*']];
            }

            /** @return array<string, string> */
            public function getServerParams(): array
            {
                return ['REMOTE_ADDR' => '8.8.8.8', 'REQUEST_METHOD' => 'GET', 'SERVER_PROTOCOL' => 'HTTP/1.1'];
            }

            /** @return array<string, string> */
            public function getCookieParams(): array
            {
                return ['a' => 'b'];
            }

            public function getMethod(): string
            {
                return 'GET';
            }

            public function getUri(): string
            {
                return '/api';
            }

            public function getProtocolVersion(): string
            {
                return '1.1';
            }
        };

        $context = (new Psr7RequestContextFactory())->fromRequest($request);

        self::assertSame('curl/8.0', $context->headers()->get('user-agent'));
        self::assertSame('8.8.8.8', $context->remoteAddress());
        self::assertSame('/api', $context->uri());
    }
}
