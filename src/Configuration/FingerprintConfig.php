<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Configuration;

use GlobusStudio\Fingerprint\Normalizer\HeaderNormalizer;

final class FingerprintConfig
{
    /** @var list<string> */
    public const DEFAULT_DENIED_HEADERS = [
        'authorization',
        'proxy-authorization',
        'cookie',
        'set-cookie',
        'x-api-key',
        'x-auth-token',
        'x-csrf-token',
        'csrf-token',
        'x-xsrf-token',
    ];

    /** @var array<string, int> */
    public const DEFAULT_WEIGHTS = [
        'browser.family' => 8,
        'browser.major' => 6,
        'browser.engine' => 4,
        'os.family' => 6,
        'os.major' => 4,
        'device.class' => 4,
        'header.accept_language' => 7,
        'header.accept_encoding' => 5,
        'header.accept' => 4,
        'client_hints.platform' => 6,
        'client_hints.mobile' => 4,
        'client_hints.brands' => 5,
        'ip.prefix' => 8,
        'ip.full' => 2,
        'proxy.chain_shape' => 3,
        'tls.protocol' => 3,
        'header.order_hash' => 2,
        'cookie.allowlisted_presence' => 3,
    ];

    /**
     * @param array<string, string> $cookieModes
     * @param list<string>          $excludedHeaders
     * @param list<string>          $disabledSignals
     * @param array<string, int>    $signalWeights
     */
    private function __construct(
        private PrivacyMode $privacyMode,
        private HashingConfig $hashingConfig,
        private TrustedProxiesConfig $trustedProxiesConfig,
        private IpPrefixingConfig $ipPrefixingConfig,
        private bool $includeClientHints,
        private bool $includeHeaderOrder,
        private bool $includeRiskSignals,
        private bool $debug,
        private bool $allowRawValues,
        private array $cookieModes,
        private array $excludedHeaders,
        private int $maxHeaderCount,
        private int $maxHeaderLength,
        private array $disabledSignals,
        private array $signalWeights,
        private ?int $ttlSeconds,
    ) {}

    public static function strict(string $secret): self
    {
        return new self(
            PrivacyMode::Strict,
            HashingConfig::production($secret),
            TrustedProxiesConfig::none(),
            new IpPrefixingConfig(24, 48, false),
            true,
            false,
            true,
            false,
            false,
            [],
            self::DEFAULT_DENIED_HEADERS,
            100,
            8192,
            [],
            self::DEFAULT_WEIGHTS,
            null,
        );
    }

    public static function balanced(string $secret): self
    {
        return new self(
            PrivacyMode::Balanced,
            HashingConfig::production($secret),
            TrustedProxiesConfig::none(),
            new IpPrefixingConfig(24, 56, false),
            true,
            false,
            true,
            false,
            false,
            [],
            self::DEFAULT_DENIED_HEADERS,
            100,
            8192,
            [],
            self::DEFAULT_WEIGHTS,
            null,
        );
    }

    public static function maximum(string $secret): self
    {
        return new self(
            PrivacyMode::Maximum,
            HashingConfig::production($secret),
            TrustedProxiesConfig::none(),
            new IpPrefixingConfig(24, 56, false),
            true,
            true,
            true,
            false,
            false,
            [],
            self::DEFAULT_DENIED_HEADERS,
            150,
            16384,
            [],
            self::DEFAULT_WEIGHTS,
            null,
        );
    }

    public static function custom(string $secret): self
    {
        return self::balanced($secret)->withPrivacyMode(PrivacyMode::Custom);
    }

    public static function create(): self
    {
        return new self(
            PrivacyMode::Custom,
            HashingConfig::development(),
            TrustedProxiesConfig::none(),
            new IpPrefixingConfig(),
            true,
            false,
            true,
            false,
            false,
            [],
            self::DEFAULT_DENIED_HEADERS,
            100,
            8192,
            [],
            self::DEFAULT_WEIGHTS,
            null,
        );
    }

    public function build(): self
    {
        return $this;
    }

    public function withSecret(string $secret, string $keyVersion = 'v1'): self
    {
        $clone = clone $this;
        $clone->hashingConfig = HashingConfig::production($secret, $this->hashingConfig->algorithmVersion(), $keyVersion);

        return $clone;
    }

    public function withPrivacyMode(PrivacyMode $privacyMode): self
    {
        $clone = clone $this;
        $clone->privacyMode = $privacyMode;

        return $clone;
    }

    /** @param list<string> $trustedProxies */
    public function withTrustedProxies(array $trustedProxies): self
    {
        $clone = clone $this;
        $clone->trustedProxiesConfig = TrustedProxiesConfig::create($trustedProxies, $this->trustedProxiesConfig->trustedHeaders());

        return $clone;
    }

    /** @param list<string> $trustedHeaders */
    public function withTrustedHeaders(array $trustedHeaders): self
    {
        $clone = clone $this;
        $clone->trustedProxiesConfig = TrustedProxiesConfig::create($this->trustedProxiesConfig->trustedProxies(), $trustedHeaders);

        return $clone;
    }

    public function withIpPrefixing(int $ipv4 = 24, int $ipv6 = 56): self
    {
        $clone = clone $this;
        $clone->ipPrefixingConfig = new IpPrefixingConfig($ipv4, $ipv6, $this->ipPrefixingConfig->allowFullIpAddress());

        return $clone;
    }

    public function allowFullIpAddress(bool $allow = true): self
    {
        $clone = clone $this;
        $clone->ipPrefixingConfig = new IpPrefixingConfig(
            $this->ipPrefixingConfig->ipv4PrefixLength(),
            $this->ipPrefixingConfig->ipv6PrefixLength(),
            $allow,
        );

        return $clone;
    }

    public function includeClientHints(bool $include = true): self
    {
        $clone = clone $this;
        $clone->includeClientHints = $include;

        return $clone;
    }

    public function includeHeaderOrder(bool $include = true): self
    {
        $clone = clone $this;
        $clone->includeHeaderOrder = $include;

        return $clone;
    }

    /** @param array<string, string> $cookieModes */
    public function includeCookies(array $cookieModes): self
    {
        $clone = clone $this;
        $clone->cookieModes = $cookieModes;

        return $clone;
    }

    /** @param list<string> $headers */
    public function excludeHeaders(array $headers): self
    {
        $clone = clone $this;
        $normalizedHeaders = array_map(static fn(string $header): string => HeaderNormalizer::normalizeHeaderName($header), $headers);
        $clone->excludedHeaders = array_values(array_unique([...self::DEFAULT_DENIED_HEADERS, ...$normalizedHeaders]));

        return $clone;
    }

    /** @param list<string> $signalNames */
    public function disableSignals(array $signalNames): self
    {
        $clone = clone $this;
        $clone->disabledSignals = array_values(array_unique($signalNames));

        return $clone;
    }

    /** @param array<string, int> $weights */
    public function withSignalWeights(array $weights): self
    {
        $clone = clone $this;
        $clone->signalWeights = [...$this->signalWeights, ...$weights];

        return $clone;
    }

    public function withDebug(bool $debug = true, bool $allowRawValues = false): self
    {
        $clone = clone $this;
        $clone->debug = $debug;
        $clone->allowRawValues = $allowRawValues;

        return $clone;
    }

    public function withTtl(?int $ttlSeconds): self
    {
        $clone = clone $this;
        $clone->ttlSeconds = $ttlSeconds === null ? null : max(1, $ttlSeconds);

        return $clone;
    }

    public function privacyMode(): PrivacyMode
    {
        return $this->privacyMode;
    }

    public function hashingConfig(): HashingConfig
    {
        return $this->hashingConfig;
    }

    public function trustedProxiesConfig(): TrustedProxiesConfig
    {
        return $this->trustedProxiesConfig;
    }

    public function ipPrefixingConfig(): IpPrefixingConfig
    {
        return $this->ipPrefixingConfig;
    }

    public function shouldIncludeClientHints(): bool
    {
        return $this->includeClientHints;
    }

    public function shouldIncludeHeaderOrder(): bool
    {
        return $this->includeHeaderOrder;
    }

    public function includeRiskSignals(): bool
    {
        return $this->includeRiskSignals;
    }

    public function debug(): bool
    {
        return $this->debug;
    }

    public function allowRawValues(): bool
    {
        return $this->allowRawValues;
    }

    public function cookieMode(string $cookieName): ?string
    {
        return $this->cookieModes[$cookieName] ?? null;
    }

    /** @return array<string, string> */
    public function cookieModes(): array
    {
        return $this->cookieModes;
    }

    public function maxHeaderCount(): int
    {
        return $this->maxHeaderCount;
    }

    public function maxHeaderLength(): int
    {
        return $this->maxHeaderLength;
    }

    public function isHeaderDenied(string $headerName): bool
    {
        return in_array(HeaderNormalizer::normalizeHeaderName($headerName), $this->excludedHeaders, true);
    }

    public function isSignalDisabled(string $signalName): bool
    {
        return in_array($signalName, $this->disabledSignals, true);
    }

    public function weightFor(string $signalName, int $default = 1): int
    {
        return (int) ($this->signalWeights[$signalName] ?? $default);
    }

    public function ttlSeconds(): ?int
    {
        return $this->ttlSeconds;
    }
}
