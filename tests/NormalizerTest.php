<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests;

use GlobusStudio\Fingerprint\Hasher\CanonicalJsonEncoder;
use GlobusStudio\Fingerprint\Normalizer\AcceptLanguageNormalizer;
use GlobusStudio\Fingerprint\Normalizer\EncodingNormalizer;
use GlobusStudio\Fingerprint\Normalizer\HeaderNormalizer;
use GlobusStudio\Fingerprint\Normalizer\UserAgentNormalizer;
use GlobusStudio\Fingerprint\Request\HeaderBag;
use PHPUnit\Framework\TestCase;

final class NormalizerTest extends TestCase
{
    public function testHeaderNamesAndValuesAreNormalized(): void
    {
        self::assertSame('x-forwarded-for', HeaderNormalizer::normalizeHeaderName(' X_FORWARDED_FOR '));
        self::assertSame('hello world', HeaderNormalizer::normalizeValue(" hello\t\nworld "));
    }

    public function testAcceptLanguageQValuesAreCanonical(): void
    {
        $normalizer = new AcceptLanguageNormalizer();

        self::assertSame('en-US,en;q=0.9,uk;q=0.7', $normalizer->normalize('en-us,en;q=.900,uk;q=0.7000'));
    }

    public function testAcceptEncodingIsLowercaseAndCanonical(): void
    {
        $normalizer = new EncodingNormalizer();

        self::assertSame('gzip,br;q=0.8,zstd', $normalizer->normalize('GZIP, br;q=.8, ZSTD'));
    }

    public function testUserAgentProfileExtractsBrowserOsAndDevice(): void
    {
        $profile = (new UserAgentNormalizer())->profile('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');

        self::assertSame('Chrome', $profile['browser.family']);
        self::assertSame('124', $profile['browser.major']);
        self::assertSame('Blink', $profile['browser.engine']);
        self::assertSame('Windows', $profile['os.family']);
        self::assertSame('desktop', $profile['device.class']);
    }

    public function testHeaderBagBuildsFromServerVariables(): void
    {
        $headers = HeaderBag::fromServer([
            'HTTP_USER_AGENT' => 'UA',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'CONTENT_TYPE' => 'application/json',
        ]);

        self::assertSame('UA', $headers->get('User-Agent'));
        self::assertSame('en-US', $headers->get('accept-language'));
        self::assertSame('application/json', $headers->get('content-type'));
        self::assertSame(['user-agent', 'accept-language', 'content-type'], $headers->order());
    }

    public function testCanonicalJsonEncoderIsDeterministic(): void
    {
        $encoder = new CanonicalJsonEncoder();

        $left = $encoder->encode(['b' => 2, 'a' => ['d' => 4, 'c' => 3]]);
        $right = $encoder->encode(['a' => ['c' => 3, 'd' => 4], 'b' => 2]);

        self::assertSame($left, $right);
        self::assertSame('{"a":{"c":3,"d":4},"b":2}', $left);
    }
}
