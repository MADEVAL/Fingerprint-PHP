<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Normalizer\IpNormalizer;
use PHPUnit\Framework\TestCase;

final class IpNormalizerTest extends TestCase
{
    public function testIpv4Prefix(): void
    {
        self::assertSame('203.0.113.0/24', IpNormalizer::prefix('203.0.113.44', 24));
    }

    public function testIpv6Prefix(): void
    {
        self::assertSame('2001:db8:abcd:1200::/56', IpNormalizer::prefix('2001:db8:abcd:1234:5678::1', 24, 56));
    }

    public function testCidrMatching(): void
    {
        self::assertTrue(IpNormalizer::matchesCidr('10.5.1.2', '10.0.0.0/8'));
        self::assertFalse(IpNormalizer::matchesCidr('11.5.1.2', '10.0.0.0/8'));
        self::assertTrue(IpNormalizer::matchesCidr('2001:db8::1', '2001:db8::/32'));
    }

    public function testIpClassification(): void
    {
        self::assertTrue(IpNormalizer::isPrivate('10.0.0.1'));
        self::assertTrue(IpNormalizer::isLoopback('127.0.0.1'));
        self::assertTrue(IpNormalizer::isLinkLocal('169.254.0.10'));
        self::assertSame(4, IpNormalizer::version('8.8.8.8'));
        self::assertSame(6, IpNormalizer::version('2001:4860:4860::8888'));
    }
}
