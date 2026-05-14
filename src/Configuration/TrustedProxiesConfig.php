<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Configuration;

use GlobusStudio\Fingerprint\Normalizer\IpNormalizer;

final readonly class TrustedProxiesConfig
{
    /** @var list<string> */
    public const DEFAULT_TRUSTED_HEADERS = [
        'forwarded',
        'x-forwarded-for',
        'x-forwarded-host',
        'x-forwarded-port',
        'x-forwarded-proto',
        'x-real-ip',
        'cf-connecting-ip',
        'true-client-ip',
        'fastly-client-ip',
    ];

    /**
     * @param list<string> $trustedProxies
     * @param list<string> $trustedHeaders
     */
    public function __construct(
        private array $trustedProxies = [],
        private array $trustedHeaders = self::DEFAULT_TRUSTED_HEADERS,
    ) {}

    public static function none(): self
    {
        return new self([], self::DEFAULT_TRUSTED_HEADERS);
    }

    /**
     * @param list<string> $trustedProxies
     * @param list<string> $trustedHeaders
     */
    public static function create(array $trustedProxies, array $trustedHeaders = self::DEFAULT_TRUSTED_HEADERS): self
    {
        return new self($trustedProxies, array_values(array_unique(array_map(static fn(string $header): string => strtolower($header), $trustedHeaders))));
    }

    public static function cloudflare(): self
    {
        return self::create(['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22'], ['cf-connecting-ip', 'x-forwarded-for', 'x-forwarded-proto']);
    }

    public static function fastly(): self
    {
        return self::create(['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24'], ['fastly-client-ip', 'x-forwarded-for', 'x-forwarded-proto']);
    }

    public static function akamai(): self
    {
        return self::create([], ['true-client-ip', 'x-forwarded-for', 'x-forwarded-proto']);
    }

    public static function awsAlb(): self
    {
        return self::create([], ['x-forwarded-for', 'x-forwarded-port', 'x-forwarded-proto']);
    }

    /** @param list<string> $trustedProxies */
    public static function nginxProxy(array $trustedProxies): self
    {
        return self::create($trustedProxies, ['x-real-ip', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host']);
    }

    public function isTrusted(string $ipAddress): bool
    {
        if ($ipAddress === '') {
            return false;
        }

        foreach ($this->trustedProxies as $trustedProxy) {
            if ($trustedProxy === '*') {
                return true;
            }

            if ($trustedProxy === $ipAddress) {
                return true;
            }

            if (str_contains($trustedProxy, '/') && IpNormalizer::matchesCidr($ipAddress, $trustedProxy)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    public function trustedProxies(): array
    {
        return $this->trustedProxies;
    }

    /** @return list<string> */
    public function trustedHeaders(): array
    {
        return $this->trustedHeaders;
    }

    public function trustsHeader(string $headerName): bool
    {
        return in_array(strtolower($headerName), $this->trustedHeaders, true);
    }
}
