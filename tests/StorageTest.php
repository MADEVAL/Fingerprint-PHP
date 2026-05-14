<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintBuilder;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Storage\InMemoryFingerprintStorage;
use GlobusStudio\Fingerprint\Tests\Support\ServerFixtures;
use PHPUnit\Framework\TestCase;

final class StorageTest extends TestCase
{
    public function testInMemoryStorageStoresLatestFirst(): void
    {
        $storage = new InMemoryFingerprintStorage();
        $config = FingerprintConfig::balanced('test-secret');
        $first = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::nginxChrome()), $config)->build();
        $second = FingerprintBuilder::fromRequestContext(RequestContext::fromArrays(ServerFixtures::apacheFirefox()), $config)->build();

        $storage->save('user-1', $first);
        $storage->save('user-1', $second);

        self::assertSame($second, $storage->findLatestBySubject('user-1'));
        self::assertCount(2, $storage->findBySubject('user-1'));

        $storage->deleteBySubject('user-1');

        self::assertNull($storage->findLatestBySubject('user-1'));
    }
}
