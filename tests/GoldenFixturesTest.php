<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Request\RequestContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GoldenFixturesTest extends TestCase
{
    /** @return iterable<string, array{0: string}> */
    public static function fixtureFiles(): iterable
    {
        foreach (glob(__DIR__ . '/Fixtures/*.json') ?: [] as $fixtureFile) {
            yield basename($fixtureFile) => [$fixtureFile];
        }
    }

    #[DataProvider('fixtureFiles')]
    public function testGoldenFingerprintOutputIsStable(string $fixtureFile): void
    {
        $fixture = json_decode((string) file_get_contents($fixtureFile), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($fixture);
        /** @var array<string, mixed> $fixture */

        $secret = $fixture['secret'] ?? null;
        self::assertIsString($secret);

        $config = FingerprintConfig::balanced($secret);

        if (($fixture['includeHeaderOrder'] ?? false) === true) {
            $config = $config->includeHeaderOrder();
        }

        if (isset($fixture['trustedProxies'])) {
            $config = $config->withTrustedProxies($this->stringList($fixture['trustedProxies']))->withTrustedHeaders($this->stringList($fixture['trustedHeaders'] ?? ['x-forwarded-for']));
        }

        $server = $fixture['server'] ?? null;
        self::assertIsArray($server);
        $cookies = $fixture['cookies'] ?? [];
        self::assertIsArray($cookies);

        $result = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays($this->stringKeyArray($server), $this->stringKeyArray($cookies)), $config)->build();

        self::assertSame($fixture['expectedId'], $result->id());
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn(mixed $item): bool => is_string($item)));
    }

    /**
     * @param array<mixed> $value
     * @return array<string, mixed>
     */
    private function stringKeyArray(array $value): array
    {
        $normalized = [];

        foreach ($value as $key => $item) {
            $normalized[(string) $key] = $item;
        }

        return $normalized;
    }
}
