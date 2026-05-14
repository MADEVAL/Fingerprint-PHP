<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use DateTimeImmutable;
use GlobusStudio\Fingerprint\Collector\FrameworkSignalCollector;
use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Configuration\HashingConfig;
use GlobusStudio\Fingerprint\Configuration\SignalConfig;
use GlobusStudio\Fingerprint\Diagnostics\FingerprintDiagnostics;
use GlobusStudio\Fingerprint\Exception\ConfigurationException;
use GlobusStudio\Fingerprint\Exception\UnsupportedEnvironmentException;
use GlobusStudio\Fingerprint\Fingerprint;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\FingerprintResult;
use GlobusStudio\Fingerprint\Hasher\CanonicalPayload;
use GlobusStudio\Fingerprint\Hasher\FingerprintHasherInterface;
use GlobusStudio\Fingerprint\Hasher\SodiumHasher;
use GlobusStudio\Fingerprint\Integration\Psr15\FingerprintMiddleware;
use GlobusStudio\Fingerprint\Integration\Psr7\Psr7RequestContextFactory;
use GlobusStudio\Fingerprint\Integration\Symfony\SymfonyRequestContextFactory;
use GlobusStudio\Fingerprint\Matcher\FingerprintMatcher;
use GlobusStudio\Fingerprint\Matcher\MatchLevel;
use GlobusStudio\Fingerprint\Normalizer\HeaderNormalizer;
use GlobusStudio\Fingerprint\Normalizer\IpNormalizer;
use GlobusStudio\Fingerprint\Normalizer\TimezoneNormalizer;
use GlobusStudio\Fingerprint\Request\HeaderBag;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Request\RequestContextFactory;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Signal\SignalStability;
use GlobusStudio\Fingerprint\Signal\SignalType;
use GlobusStudio\Fingerprint\Tests\Support\ServerFixtures;
use PHPUnit\Framework\TestCase;

final class CoverageEdgeCasesTest extends TestCase
{
    public function testConfigurationAndSmallUtilitiesEdgeCases(): void
    {
        $this->expectException(ConfigurationException::class);

        new HashingConfig('');
    }

    public function testSignalConfigDiagnosticsTimezoneAndHeaderHelpers(): void
    {
        $signalConfig = new SignalConfig(7, false);
        $diagnostics = new FingerprintDiagnostics();
        $headers = new HeaderBag(['X-Test' => 'a']);
        $headers->set('x-test', 'b');
        $headers->set('X-Empty', new \stdClass());

        $diagnostics->addUnavailableCollector('collector');

        self::assertSame(7, $signalConfig->weight());
        self::assertFalse($signalConfig->enabled());
        self::assertSame(['collector'], $diagnostics->unavailableCollectors());
        self::assertSame('UTC', (new TimezoneNormalizer())->normalize(' UTC '));
        self::assertSame('text/html;level=1,application/json;q=1', HeaderNormalizer::normalizeCommaSeparatedQValues('TEXT/HTML;LEVEL=1;, application/json;q=1.000'));
        self::assertSame('a, b', $headers->get('x-test'));
        self::assertSame('', $headers->get('x-empty'));
        self::assertSame(['x-test', 'x-empty'], $headers->names());
    }

    public function testIpNormalizerEdgeCases(): void
    {
        self::assertNull(IpNormalizer::version('not-an-ip'));
        self::assertNull(IpNormalizer::prefix('not-an-ip'));
        self::assertSame('0.0.0.0/0', IpNormalizer::prefix('203.0.113.44', 0));
        self::assertSame('2001:db8:abcd:1234:8000::/65', IpNormalizer::prefix('2001:db8:abcd:1234:ffff::1', 24, 65));
        self::assertSame('::/0', IpNormalizer::prefix('2001:db8::1', 24, 0));
        self::assertTrue(IpNormalizer::matchesCidr('8.8.8.8', '8.8.8.8'));
        self::assertFalse(IpNormalizer::matchesCidr('8.8.8.8', '2001:db8::/32'));
        self::assertFalse(IpNormalizer::matchesCidr('8.8.8.8', 'bad-cidr/24'));
        self::assertFalse(IpNormalizer::matchesCidr('8.8.8.8', '8.8.4.0/24'));
    }

    public function testNetworkCollectorEdgeCases(): void
    {
        $invalid = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome(['REMOTE_ADDR' => 'not-an-ip'])), FingerprintConfig::balanced('test-secret'))->build();
        $cloudflare = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome([
            'REMOTE_ADDR' => '10.0.0.10',
            'HTTP_CF_CONNECTING_IP' => '203.0.113.7',
        ])), FingerprintConfig::balanced('test-secret')->withTrustedProxies(['10.0.0.0/8'])->withTrustedHeaders(['cf-connecting-ip']))->build();
        $trueClient = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome([
            'REMOTE_ADDR' => '10.0.0.10',
            'HTTP_TRUE_CLIENT_IP' => '203.0.113.8',
        ])), FingerprintConfig::balanced('test-secret')->withTrustedProxies(['10.0.0.0/8'])->withTrustedHeaders(['true-client-ip']))->build();
        $realIp = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome([
            'REMOTE_ADDR' => '10.0.0.10',
            'HTTP_X_REAL_IP' => '203.0.113.9',
        ])), FingerprintConfig::balanced('test-secret')->withTrustedProxies(['10.0.0.0/8'])->withTrustedHeaders(['x-real-ip']))->build();

        self::assertContains('ip.invalid', $invalid->ignoredSignalNames());
        self::assertSame('203.0.113.0/24', $cloudflare->signalValue('ip.prefix'));
        self::assertSame('203.0.113.0/24', $trueClient->signalValue('ip.prefix'));
        self::assertSame('203.0.113.0/24', $realIp->signalValue('ip.prefix'));
    }

    public function testFrameworkRuntimeFallbacksAndEmptyHeaderOrder(): void
    {
        $collector = new FrameworkSignalCollector();
        $config = FingerprintConfig::balanced('test-secret');
        $roadrunner = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['RR_MODE' => 'http'])), $config);
        $swoole = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['SWOOLE_HTTP_HOST' => 'example.com'])), $config);
        $emptyOrder = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(['REMOTE_ADDR' => '8.8.8.8']), $config->includeHeaderOrder())->build();

        self::assertSame('roadrunner', $roadrunner->get('framework.runtime')?->normalizedValue());
        self::assertSame('swoole', $swoole->get('framework.runtime')?->normalizedValue());
        self::assertNull($emptyOrder->signalValue('header.order_hash'));
    }

    public function testBuilderGlobalsHasherLoggerAndScoreEdges(): void
    {
        $originalServer = $_SERVER;
        $_SERVER = ServerFixtures::nginxChrome();

        try {
            $fromGlobals = (new Fingerprint(FingerprintConfig::balanced('test-secret')))->fromGlobals();
        } finally {
            $_SERVER = $originalServer;
        }

        $hasher = new class implements FingerprintHasherInterface {
            public function hash(CanonicalPayload $payload, HashingConfig $config): string
            {
                return 'custom-hash';
            }
        };
        $logger = new class {
            /** @var list<array{0: string, 1: array<string, mixed>}> */
            public array $warnings = [];

            /** @param array<string, mixed> $context */
            public function warning(string $message, array $context = []): void
            {
                $this->warnings[] = [$message, $context];
            }
        };
        $throwingCollector = new class implements \GlobusStudio\Fingerprint\Collector\SignalCollectorInterface {
            public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
            {
                throw new \RuntimeException('broken');
            }
        };

        $customHash = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome()), FingerprintConfig::balanced('test-secret'))
            ->withHasher($hasher)
            ->withLogger($logger)
            ->withCollector($throwingCollector)
            ->build();
        $noSignals = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(['REMOTE_ADDR' => 'not-an-ip']), FingerprintConfig::balanced('test-secret')->disableSignals(array_keys(FingerprintConfig::DEFAULT_WEIGHTS)))->build();

        self::assertStringStartsWith('gsfp_v1_', $fromGlobals->id());
        self::assertSame('custom-hash', $customHash->id());
        self::assertSame('Fingerprint collector failed.', $logger->warnings[0][0]);
        self::assertSame(0, $noSignals->stabilityScore());
    }

    public function testMiddlewareErrorPathsAndAdapterFallbacks(): void
    {
        $middleware = new FingerprintMiddleware(FingerprintConfig::balanced('test-secret'));
        $requestReturningString = new class {
            public function withAttribute(string $name, object $value): string
            {
                return 'bad-request';
            }
        };
        $handlerWithoutHandle = new \stdClass();
        $handlerReturningString = new class {
            public function handle(object $request): string
            {
                return 'bad-response';
            }
        };

        try {
            $middleware->process($requestReturningString, $handlerWithoutHandle);
            self::fail('Expected request exception.');
        } catch (UnsupportedEnvironmentException $exception) {
            self::assertStringContainsString('withAttribute', $exception->getMessage());
        }

        try {
            $middleware->process(new \stdClass(), $handlerWithoutHandle);
            self::fail('Expected handler exception.');
        } catch (UnsupportedEnvironmentException $exception) {
            self::assertStringContainsString('handle', $exception->getMessage());
        }

        try {
            $middleware->process(new \stdClass(), $handlerReturningString);
            self::fail('Expected response exception.');
        } catch (UnsupportedEnvironmentException $exception) {
            self::assertStringContainsString('response object', $exception->getMessage());
        }

        $badPsrRequest = new class {
            public function getHeaders(): string
            {
                return 'bad';
            }

            public function getServerParams(): string
            {
                return 'bad';
            }

            public function getCookieParams(): string
            {
                return 'bad';
            }

            public function getMethod(): array
            {
                return [];
            }

            public function getUri(): array
            {
                return [];
            }

            public function getProtocolVersion(): array
            {
                return [];
            }
        };
        $context = (new Psr7RequestContextFactory())->fromRequest($badPsrRequest);
        $symfonyContext = (new SymfonyRequestContextFactory())->fromRequest(new class {
            public object $headers;
            public object $server;
            public object $cookies;

            public function __construct()
            {
                $this->headers = new \stdClass();
                $this->server = new class {
                    public function all(): string
                    {
                        return 'bad';
                    }
                };
                $this->cookies = new \stdClass();
            }

            public function getMethod(): array
            {
                return [];
            }

            public function getRequestUri(): array
            {
                return [];
            }

            public function getClientIp(): array
            {
                return [];
            }
        });

        self::assertSame('GET', $context->method());
        self::assertSame('/', $context->uri());
        self::assertSame('HTTP/1.1', $context->protocol());
        self::assertSame('', $symfonyContext->remoteAddress());
    }

    public function testMatcherAccessorsAndSodiumHasherWhenAvailable(): void
    {
        $currentSignals = new SignalSet([
            new Signal('stable.same', SignalType::Header, null, 'same', 1, SignalStability::Stable, SignalSensitivity::Low, 'test'),
            new Signal('volatile.changed', SignalType::Header, null, 'new', 1, SignalStability::Volatile, SignalSensitivity::Low, 'test'),
        ]);
        $knownSignals = new SignalSet([
            new Signal('stable.same', SignalType::Header, null, 'same', 1, SignalStability::Stable, SignalSensitivity::Low, 'test'),
            new Signal('volatile.changed', SignalType::Header, null, 'old', 1, SignalStability::Volatile, SignalSensitivity::Low, 'test'),
        ]);
        $current = new FingerprintResult('a', 'gsfp-v1', 'balanced', new DateTimeImmutable(), 0, 0, 0, 0, $currentSignals, []);
        $known = new FingerprintResult('b', 'gsfp-v1', 'balanced', new DateTimeImmutable(), 0, 0, 0, 0, $knownSignals, []);
        $match = (new FingerprintMatcher(['stable.same' => 10, 'volatile.changed' => 1]))->compare($current, $known);

        self::assertSame(MatchLevel::Similar, $match->level());
        self::assertTrue($match->partialMatch());
        self::assertSame(1, $match->stableSignalsMatched());
        self::assertSame(1, $match->volatileSignalsChanged());
        self::assertSame(['volatile.changed'], $match->changedSignals());
        self::assertFalse(MatchLevel::Similar->isSuspicious());

        if (function_exists('sodium_crypto_generichash')) {
            $hash = (new SodiumHasher())->hash(new CanonicalPayload(['signals' => ['a' => 'b']]), HashingConfig::production('test-secret'));
            self::assertStringStartsWith('gsfp_v1_', $hash);
        } else {
            self::assertTrue(true);
        }
    }

    public function testRequestContextFactoryAndRemainingAccessors(): void
    {
        $context = (new RequestContextFactory())->fromArrays(ServerFixtures::nginxChrome(), ['a' => 'b']);
        $signal = new Signal('special', SignalType::Header, 'raw', 'secret', 1, SignalStability::Stable, SignalSensitivity::Special, 'test');

        self::assertSame(['a' => 'b'], $context->cookies()->all());
        self::assertInstanceOf(\DateTimeImmutable::class, $context->receivedAt());
        self::assertSame('[omitted]', $signal->toSafeArray(true)['normalizedValue']);
        self::assertArrayNotHasKey('rawValue', $signal->toSafeArray(true));
    }
}
