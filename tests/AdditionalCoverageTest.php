<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use DateTimeImmutable;
use GlobusStudio\Fingerprint\Collector\FrameworkSignalCollector;
use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Configuration\HashingConfig;
use GlobusStudio\Fingerprint\Configuration\PrivacyMode;
use GlobusStudio\Fingerprint\Configuration\TrustedProxiesConfig;
use GlobusStudio\Fingerprint\Fingerprint;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\FingerprintResult;
use GlobusStudio\Fingerprint\Hasher\CanonicalPayload;
use GlobusStudio\Fingerprint\Hasher\HmacSha256Hasher;
use GlobusStudio\Fingerprint\Integration\Laminas\LaminasRequestContextFactory;
use GlobusStudio\Fingerprint\Integration\Laravel\LaravelRequestContextFactory;
use GlobusStudio\Fingerprint\Integration\Psr15\FingerprintMiddleware;
use GlobusStudio\Fingerprint\Integration\Slim\SlimRequestContextFactory;
use GlobusStudio\Fingerprint\Integration\Symfony\SymfonyRequestContextFactory;
use GlobusStudio\Fingerprint\Matcher\FingerprintMatcher;
use GlobusStudio\Fingerprint\Matcher\MatchLevel;
use GlobusStudio\Fingerprint\Request\CookieBag;
use GlobusStudio\Fingerprint\Request\HeaderBag;
use GlobusStudio\Fingerprint\Request\NativeServerRequestFactory;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Request\RequestContextFactory;
use GlobusStudio\Fingerprint\Request\ServerBag;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Signal\SignalStability;
use GlobusStudio\Fingerprint\Signal\SignalType;
use GlobusStudio\Fingerprint\Tests\Support\ServerFixtures;
use PHPUnit\Framework\TestCase;

final class AdditionalCoverageTest extends TestCase
{
    public function testFluentConfigurationAndTrustedProxyPresets(): void
    {
        $config = FingerprintConfig::create()
            ->withSecret('secret', 'k2')
            ->withPrivacyMode(PrivacyMode::Custom)
            ->withTrustedProxies(['10.0.0.0/8'])
            ->withTrustedHeaders(['x-forwarded-for'])
            ->withIpPrefixing(20, 48)
            ->allowFullIpAddress()
            ->includeClientHints(false)
            ->includeHeaderOrder()
            ->includeCookies(['device' => 'hash'])
            ->excludeHeaders(['x-private-debug'])
            ->disableSignals(['browser.engine'])
            ->withSignalWeights(['custom.signal' => 9])
            ->withDebug(true, true)
            ->withTtl(120)
            ->build();

        self::assertSame(PrivacyMode::Custom, $config->privacyMode());
        self::assertSame('k2', $config->hashingConfig()->keyVersion());
        self::assertFalse($config->hashingConfig()->devMode());
        self::assertTrue($config->trustedProxiesConfig()->isTrusted('10.10.10.10'));
        self::assertTrue($config->trustedProxiesConfig()->trustsHeader('x-forwarded-for'));
        self::assertSame(20, $config->ipPrefixingConfig()->ipv4PrefixLength());
        self::assertSame(48, $config->ipPrefixingConfig()->ipv6PrefixLength());
        self::assertTrue($config->ipPrefixingConfig()->allowFullIpAddress());
        self::assertFalse($config->shouldIncludeClientHints());
        self::assertTrue($config->shouldIncludeHeaderOrder());
        self::assertTrue($config->includeRiskSignals());
        self::assertTrue($config->debug());
        self::assertTrue($config->allowRawValues());
        self::assertSame('hash', $config->cookieMode('device'));
        self::assertTrue($config->isHeaderDenied('X-Private-Debug'));
        self::assertTrue($config->isSignalDisabled('browser.engine'));
        self::assertSame(9, $config->weightFor('custom.signal'));
        self::assertSame(120, $config->ttlSeconds());

        self::assertTrue(TrustedProxiesConfig::cloudflare()->trustsHeader('cf-connecting-ip'));
        self::assertTrue(TrustedProxiesConfig::fastly()->trustsHeader('fastly-client-ip'));
        self::assertTrue(TrustedProxiesConfig::akamai()->trustsHeader('true-client-ip'));
        self::assertTrue(TrustedProxiesConfig::awsAlb()->trustsHeader('x-forwarded-port'));
        self::assertTrue(TrustedProxiesConfig::nginxProxy(['127.0.0.1'])->isTrusted('127.0.0.1'));
    }

    public function testCookieHashAndNormalizedModes(): void
    {
        $request = RequestContext::fromArrays(ServerFixtures::nginxChrome(), [
            'device' => 'secret-device-cookie',
            'theme' => ' dark ',
        ]);
        $config = FingerprintConfig::balanced('test-secret')->includeCookies([
            'device' => 'hash',
            'theme' => 'normalized',
        ]);

        $result = FingerprintBuilder::fromRequestContext($request, $config)->build();

        self::assertSame(hash_hmac('sha256', 'secret-device-cookie', 'test-secret'), $result->signalValue('cookie.device.hash'));
        self::assertSame('dark', $result->signalValue('cookie.theme.normalized'));
        self::assertStringNotContainsString('secret-device-cookie', json_encode($result->toSafeArray(), JSON_THROW_ON_ERROR));
    }

    public function testTlsSignalsAndClientCertificateDataAreCollectedSafely(): void
    {
        $server = ServerFixtures::nginxChrome([
            'SSL_PROTOCOL' => 'TLSv1.3',
            'SSL_CIPHER' => 'TLS_AES_256_GCM_SHA384',
            'SSL_CLIENT_S_DN' => 'CN=Sensitive User',
        ]);
        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays($server), FingerprintConfig::balanced('test-secret'))->build();
        $safeJson = json_encode($result->toSafeArray(), JSON_THROW_ON_ERROR);

        self::assertSame('TLSv1.3', $result->signalValue('tls.protocol'));
        self::assertContains('tls.protocol', $result->usedSignalNames());
        self::assertContains('tls.cipher', $result->ignoredSignalNames());
        self::assertStringNotContainsString('CN=Sensitive User', $safeJson);
    }

    public function testFacadeNativeFactoryRequestBagsAndHasherVariants(): void
    {
        $context = NativeServerRequestFactory::create(ServerFixtures::nginxChrome(), ['session' => 'abc']);
        $result = (new Fingerprint(FingerprintConfig::balanced('test-secret')))->fromRequestContext($context);
        $headers = new HeaderBag(['X-Test' => ['a', 'b'], 'X-Object' => new class {
            public function __toString(): string
            {
                return 'object-value';
            }
        }]);
        $server = new ServerBag(['A' => 'B']);
        $cookies = new CookieBag(['c' => 'd']);
        $developmentConfig = HashingConfig::development('dev-secret');
        $base64Config = new HashingConfig('secret', 'gsfp-v1', 'v1', false, 'base64url');
        $hash = (new HmacSha256Hasher())->hash(new CanonicalPayload(['signals' => ['a' => 'b']]), $base64Config);

        self::assertStringStartsWith('gsfp_v1_', $result->id());
        self::assertSame('a, b', $headers->get('x-test'));
        self::assertSame('object-value', $headers->get('x-object'));
        self::assertTrue($server->has('A'));
        self::assertSame(['A' => 'B'], $server->all());
        self::assertTrue($cookies->has('c'));
        self::assertSame(['c' => 'd'], $cookies->all());
        self::assertTrue($developmentConfig->devMode());
        self::assertSame('dev-secret', $developmentConfig->secret());
        self::assertStringNotContainsString('+', $hash);
        self::assertStringNotContainsString('/', $hash);
    }

    public function testPsr15SymfonyAndLaravelAdapters(): void
    {
        $psrRequest = new class {
            public ?object $fingerprint = null;

            public function withAttribute(string $name, object $value): self
            {
                if ($name === 'globus_fingerprint') {
                    $this->fingerprint = $value;
                }

                return $this;
            }

            /** @return array<string, list<string>> */
            public function getHeaders(): array
            {
                return ['User-Agent' => ['curl/8.0']];
            }
            /** @return array<string, string> */
            public function getServerParams(): array
            {
                return ['REMOTE_ADDR' => '8.8.8.8', 'REQUEST_METHOD' => 'GET'];
            }
        };
        $handler = new class {
            public function handle(object $request): object
            {
                return (object) ['request' => $request];
            }
        };
        $response = (new FingerprintMiddleware(FingerprintConfig::balanced('test-secret')))->process($psrRequest, $handler);

        $bag = new class {
            /** @return array<string, string> */
            public function all(): array
            {
                return ['REMOTE_ADDR' => '8.8.4.4', 'REQUEST_METHOD' => 'POST', 'SERVER_PROTOCOL' => 'HTTP/1.1'];
            }
        };
        $headersBag = new class {
            /** @return array<string, string> */
            public function all(): array
            {
                return ['User-Agent' => 'curl/8.0'];
            }
        };
        $symfonyRequest = new class ($bag, $headersBag) {
            public object $server;
            public object $headers;
            public object $cookies;

            public function __construct(object $server, object $headers)
            {
                $this->server = $server;
                $this->headers = $headers;
                $this->cookies = $headers;
            }

            public function getMethod(): string
            {
                return 'POST';
            }

            public function getRequestUri(): string
            {
                return '/symfony';
            }

            public function getClientIp(): string
            {
                return '8.8.4.4';
            }
        };
        $symfonyContext = (new SymfonyRequestContextFactory())->fromRequest($symfonyRequest);
        $laravelContext = (new LaravelRequestContextFactory())->fromRequest($symfonyRequest);

        self::assertSame($psrRequest, get_object_vars($response)['request'] ?? null);
        self::assertInstanceOf(FingerprintResult::class, $psrRequest->fingerprint);
        self::assertSame('8.8.4.4', $symfonyContext->remoteAddress());
        self::assertSame('8.8.4.4', $laravelContext->remoteAddress());
    }

    public function testLaminasAndSlimAdaptersUsePsr7Requests(): void
    {
        $request = new class {
            /** @return array<string, list<string>> */
            public function getHeaders(): array
            {
                return ['User-Agent' => ['curl/8.0']];
            }

            /** @return array<string, string> */
            public function getServerParams(): array
            {
                return ['REMOTE_ADDR' => '1.1.1.1', 'REQUEST_METHOD' => 'GET'];
            }

            /** @return array<string, string> */
            public function getCookieParams(): array
            {
                return [];
            }
        };

        self::assertSame('1.1.1.1', (new LaminasRequestContextFactory())->fromRequest($request)->remoteAddress());
        self::assertSame('1.1.1.1', (new SlimRequestContextFactory())->fromRequest($request)->remoteAddress());
    }

    public function testFrameworkCollectorDetectsFrameworkAndRuntimeContext(): void
    {
        $collector = new FrameworkSignalCollector();
        $config = FingerprintConfig::balanced('test-secret');

        $laravelSignals = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['LARAVEL_START' => '1'])), $config);
        $symfonySignals = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['APP_RUNTIME' => 'Symfony\\Component\\Runtime\\SymfonyRuntime'])), $config);
        $laminasSignals = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['LAMINAS_ENV' => 'production'])), $config);
        $slimSignals = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['SLIM_MODE' => 'production'])), $config);
        $runtimeSignals = $collector->collect(RequestContext::fromArrays(ServerFixtures::nginxChrome(['SERVER_SOFTWARE' => 'FrankenPHP'])), $config);

        self::assertSame('laravel', $laravelSignals->get('framework.name')?->normalizedValue());
        self::assertSame('symfony', $symfonySignals->get('framework.name')?->normalizedValue());
        self::assertSame('laminas', $laminasSignals->get('framework.name')?->normalizedValue());
        self::assertSame('slim', $slimSignals->get('framework.name')?->normalizedValue());
        self::assertSame('frankenphp', $runtimeSignals->get('framework.runtime')?->normalizedValue());
        self::assertFalse($runtimeSignals->get('framework.runtime')->included());
    }

    public function testMatcherUnknownResultAndResultAccessors(): void
    {
        $emptyResult = new FingerprintResult('id-a', 'gsfp-v1', 'balanced', new DateTimeImmutable(), 0, 0, 0, 0, new SignalSet(), []);
        $otherEmptyResult = new FingerprintResult('id-b', 'gsfp-v1', 'balanced', new DateTimeImmutable(), 0, 0, 0, 0, new SignalSet(), []);
        $unknownMatch = (new FingerprintMatcher())->compare($emptyResult, $otherEmptyResult);

        self::assertSame(MatchLevel::Unknown, $unknownMatch->level());
        self::assertFalse($unknownMatch->partialMatch());
        self::assertSame(['no_comparable_signals'], $unknownMatch->riskReasons());
        self::assertSame('gsfp-v1', $emptyResult->version());
        self::assertSame('balanced', $emptyResult->profile());
        self::assertInstanceOf(DateTimeImmutable::class, $emptyResult->createdAt());
        self::assertSame([], $emptyResult->environment());
        self::assertSame([], $emptyResult->toStorageArray()['usedSignalNames']);
    }

    public function testSignalSetAndSignalAccessors(): void
    {
        $included = new Signal('a', SignalType::Header, 'raw', 'normalized', 1, SignalStability::Stable, SignalSensitivity::Low, 'source');
        $ignored = new Signal('b', SignalType::Header, 'raw', 'normalized', 1, SignalStability::Volatile, SignalSensitivity::High, 'source', false, 'ignored');
        $signals = new SignalSet([$included]);
        $signals->add($ignored);

        self::assertSame(2, $signals->count());
        self::assertSame($included, $signals->get('a'));
        self::assertSame([$included], $signals->included());
        self::assertSame([$ignored], $signals->ignored());
        self::assertSame(['a' => 'normalized'], $signals->toHashMap());
        self::assertSame('a', $included->name());
        self::assertSame('raw', $included->rawValue());
        self::assertSame(1, $included->weight());
        self::assertSame('source', $included->source());
        self::assertTrue($included->included());
        self::assertSame('included', $included->reason());
        self::assertSame('medium', $included->reliability());
    }
}
