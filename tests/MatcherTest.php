<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Matcher\FingerprintMatcher;
use GlobusStudio\Fingerprint\Matcher\MatchLevel;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Tests\Support\ServerFixtures;
use PHPUnit\Framework\TestCase;

final class MatcherTest extends TestCase
{
    public function testExactMatchReturnsSame(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());
        $config = FingerprintConfig::balanced('test-secret');
        $result = FingerprintBuilder::fromRequestContext($request, $config)->build();

        $match = (new FingerprintMatcher())->compare($result, $result);

        self::assertSame(MatchLevel::Same, $match->level());
        self::assertTrue($match->exactMatch());
        self::assertSame(0, $match->distance());
    }

    public function testSmallVolatileChangeIsSimilarOrSameWhenPrefixIsStable(): void
    {
        $config = FingerprintConfig::balanced('test-secret');
        $known = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome()), $config)->build();
        $current = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome(['REMOTE_ADDR' => '203.0.113.88'])), $config)->build();

        $match = (new FingerprintMatcher())->compare($current, $known);

        self::assertContains($match->level(), [MatchLevel::Same, MatchLevel::Similar]);
        self::assertLessThanOrEqual(20, $match->distance());
    }

    public function testLargeStableChangeIsSuspicious(): void
    {
        $config = FingerprintConfig::balanced('test-secret');
        $known = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome()), $config)->build();
        $current = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::apacheFirefox(['REMOTE_ADDR' => '8.8.8.8'])), $config)->build();

        $match = (new FingerprintMatcher())->compare($current, $known);

        self::assertSame(MatchLevel::Suspicious, $match->level());
        self::assertContains('browser.family_changed', $match->riskReasons());
        self::assertGreaterThan(50, $match->distance());
    }
}
