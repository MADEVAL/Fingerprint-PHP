<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Request;

final class NativeServerRequestFactory
{
    /**
     * @param array<string, mixed>|null $server
     * @param array<string, mixed>|null $cookies
     */
    public static function create(?array $server = null, ?array $cookies = null): RequestContext
    {
        return RequestContext::fromArrays(self::stringKeyArray($server ?? $_SERVER), self::stringKeyArray($cookies ?? $_COOKIE));
    }

    /**
     * @param array<mixed> $value
     * @return array<string, mixed>
     */
    private static function stringKeyArray(array $value): array
    {
        $normalized = [];

        foreach ($value as $key => $item) {
            $normalized[(string) $key] = $item;
        }

        return $normalized;
    }
}
