<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Redaction\RedactorInterface;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Tests\Support\ServerFixtures;
use PHPUnit\Framework\TestCase;

final class SecurityAndPrivacyTest extends TestCase
{
    public function testAuthorizationAndCookieHeadersAreExcludedFromSafeOutput(): void
    {
        $server = ServerFixtures::nginxChrome([
            'HTTP_AUTHORIZATION' => 'Bearer extremely-secret-token',
            'HTTP_COOKIE' => 'PHPSESSID=secret-session; app=secret',
            'HTTP_X_API_KEY' => 'secret-api-key',
        ]);

        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays($server), FingerprintConfig::balanced('test-secret'))->build();
        $safeJson = json_encode($result->toSafeArray(), JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('extremely-secret-token', $safeJson);
        self::assertStringNotContainsString('secret-session', $safeJson);
        self::assertStringNotContainsString('secret-api-key', $safeJson);
        self::assertNotContains('header.authorization', $result->usedSignalNames());
    }

    public function testCookieValuesAreIgnoredUnlessAllowlisted(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome(), ['device_consent' => 'yes-secret']);

        $withoutCookie = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret'))->build();
        $withCookie = FingerprintBuilder::fromRequestContext($request, FingerprintConfig::balanced('test-secret')->includeCookies(['device_consent' => 'presence']))->build();

        self::assertNotContains('cookie.device_consent.presence', $withoutCookie->usedSignalNames());
        self::assertContains('cookie.device_consent.presence', $withCookie->usedSignalNames());
        self::assertStringNotContainsString('yes-secret', json_encode($withCookie->toSafeArray(), JSON_THROW_ON_ERROR));
    }

    public function testSpoofedForwardedForIsIgnoredWhenRemoteIsUntrusted(): void
    {
        $server = ServerFixtures::nginxChrome([
            'REMOTE_ADDR' => '198.51.100.10',
            'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
        ]);

        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays($server), FingerprintConfig::balanced('test-secret'))->build();

        self::assertSame('198.51.100.0/24', $result->signalValue('ip.prefix'));
        self::assertSame(35, $result->riskScore());
    }

    public function testTrustedProxyAllowsForwardedForResolution(): void
    {
        $server = ServerFixtures::nginxChrome([
            'REMOTE_ADDR' => '10.0.0.10',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.44, 10.0.0.9',
        ]);
        $config = FingerprintConfig::balanced('test-secret')->withTrustedProxies(['10.0.0.0/8'])->withTrustedHeaders(['x-forwarded-for']);

        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays($server), $config)->build();

        self::assertSame('203.0.113.0/24', $result->signalValue('ip.prefix'));
        self::assertContains('proxy.chain_shape', $result->usedSignalNames());
    }

    public function testSafeArrayDoesNotExposeRawHighSensitivityValues(): void
    {
        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome()), FingerprintConfig::balanced('test-secret')->includeCookies(['device' => 'hash']))->build();
        $safeJson = json_encode($result->toSafeArray(), JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('rawValue', $safeJson);
        self::assertStringNotContainsString('203.0.113.44', $safeJson);
    }

    public function testCustomRedactorCanControlSafeOutput(): void
    {
        $redactor = new class implements RedactorInterface {
            public function redact(mixed $value, SignalSensitivity $sensitivity): mixed
            {
                return 'redacted-' . $sensitivity->value;
            }
        };
        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome()), FingerprintConfig::balanced('test-secret'))->build();
        $safe = $result->toSafeArray(false, $redactor);
        self::assertIsArray($safe['signals']);
        $normalizedValues = array_column($safe['signals'], 'normalizedValue');

        self::assertContains('redacted-low', $normalizedValues);
        self::assertContains('redacted-medium', $normalizedValues);
    }

    public function testOverlongHeadersAreReportedAndIgnored(): void
    {
        $server = ServerFixtures::nginxChrome([
            'HTTP_ACCEPT_LANGUAGE' => str_repeat('x', 9000),
        ]);
        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays($server), FingerprintConfig::balanced('test-secret'))->build();

        self::assertContains('header.length_exceeded', $result->ignoredSignalNames());
        self::assertNotContains('header.accept_language', $result->usedSignalNames());
    }
}
