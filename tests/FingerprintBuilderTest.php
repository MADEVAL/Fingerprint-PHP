<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Collector\SignalCollectorInterface;
use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Tests\Support\ServerFixtures;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class FingerprintBuilderTest extends TestCase
{
    public function testBuildsStableBalancedFingerprint(): void
    {
        $config = FingerprintConfig::balanced('test-secret');
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());

        $first = FingerprintBuilder::fromRequestContext($request, $config)->build();
        $second = FingerprintBuilder::fromRequestContext($request, $config)->build();

        self::assertSame($first->id(), $second->id());
        self::assertStringStartsWith('gsfp_v1_', $first->id());
        self::assertSame('Chrome', $first->signalValue('browser.family'));
        self::assertSame('203.0.113.0/24', $first->signalValue('ip.prefix'));
        self::assertContains('browser.family', $first->usedSignalNames());
        self::assertGreaterThan(30, $first->confidence());
        self::assertLessThanOrEqual(100, $first->entropyScore());
        self::assertLessThanOrEqual(100, $first->stabilityScore());
    }

    public function testStrictAndBalancedProfilesDoNotIncludeFullIp(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());

        $strict = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::strict('test-secret'))->build();
        $balanced = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret'))->build();

        self::assertNotContains('ip.full', $strict->usedSignalNames());
        self::assertNotContains('ip.full', $balanced->usedSignalNames());
    }

    public function testMaximumProfileCanExplicitlyIncludeFullIp(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());
        $config = FingerprintConfig::maximum('test-secret')->allowFullIpAddress();
        $result = FingerprintBuilder::fromRequestContext($request, $config)->build();

        self::assertContains('ip.full', $result->usedSignalNames());
        self::assertSame('203.0.113.44', $result->signalValue('ip.full'));
    }

    public function testHeaderOrderIsOptionalAndMarkedWithReliability(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());
        $withoutOrder = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret'))->build();
        $withOrder = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret')->includeHeaderOrder())->build();

        self::assertNull($withoutOrder->signalValue('header.order_hash'));
        self::assertIsString($withOrder->signalValue('header.order_hash'));
        self::assertNotSame($withoutOrder->id(), $withOrder->id());
    }

    public function testTtlAndExportMetadataAreAvailable(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());
        $result = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret')->withTtl(3600))->build();
        $safe = $result->toSafeArray();
        $export = $result->toExportArray();

        self::assertSame(3600, $result->ttlSeconds());
        self::assertNotNull($result->expiresAt());
        self::assertSame(3600, $safe['ttlSeconds']);
        self::assertArrayHasKey('explanation', $export);
    }

    public function testLoggerReceivesCollectorFailures(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome());
        $logger = new class {
            /** @var list<array{0: string, 1: string, 2: array<string, mixed>}> */
            public array $records = [];

            /** @param array<string, mixed> $context */
            public function log(string $level, string $message, array $context = []): void
            {
                $this->records[] = [$level, $message, $context];
            }
        };
        $collector = new class implements SignalCollectorInterface {
            public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
            {
                throw new RuntimeException('collector failed intentionally');
            }
        };

        $result = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret'))
            ->withLogger($logger)
            ->withCollector($collector)
            ->build();

        self::assertCount(1, $logger->records);
        self::assertSame('warning', $logger->records[0][0]);
        self::assertNotSame([], $result->diagnostics()->unavailableCollectors());
    }
}
