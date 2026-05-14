<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Normalizer;

final class IpNormalizer
{
    public static function isValid(string $ipAddress): bool
    {
        return filter_var($ipAddress, FILTER_VALIDATE_IP) !== false;
    }

    public static function version(string $ipAddress): ?int
    {
        if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return 4;
        }

        if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return 6;
        }

        return null;
    }

    public static function prefix(string $ipAddress, int $ipv4PrefixLength = 24, int $ipv6PrefixLength = 56): ?string
    {
        $version = self::version($ipAddress);

        if ($version === 4) {
            $prefix = max(0, min(32, $ipv4PrefixLength));
            /** @var int $ipLong */
            $ipLong = ip2long($ipAddress);

            $mask = $prefix === 0 ? 0 : ((-1 << (32 - $prefix)) & 0xFFFFFFFF);
            $network = long2ip($ipLong & $mask);

            return $network . '/' . $prefix;
        }

        if ($version === 6) {
            $prefix = max(0, min(128, $ipv6PrefixLength));
            /** @var string $packed */
            $packed = inet_pton($ipAddress);

            /** @var array<int, int> $unpackedBytes */
            $unpackedBytes = unpack('C*', $packed);

            $bytes = array_values($unpackedBytes);
            $remainingBits = $prefix;

            foreach ($bytes as $index => $byte) {
                if ($remainingBits >= 8) {
                    $remainingBits -= 8;
                    continue;
                }

                if ($remainingBits > 0) {
                    $bytes[$index] = (int) $byte & (0xFF << (8 - $remainingBits));
                    $remainingBits = 0;
                    continue;
                }

                $bytes[$index] = 0;
            }

            $network = inet_ntop(pack('C*', ...$bytes));

            return ($network === false ? null : $network . '/' . $prefix);
        }

        return null;
    }

    public static function isPrivate(string $ipAddress): bool
    {
        return self::isValid($ipAddress) && filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false;
    }

    public static function isReserved(string $ipAddress): bool
    {
        return self::isValid($ipAddress) && filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false;
    }

    public static function isLoopback(string $ipAddress): bool
    {
        return str_starts_with($ipAddress, '127.') || $ipAddress === '::1';
    }

    public static function isLinkLocal(string $ipAddress): bool
    {
        return str_starts_with($ipAddress, '169.254.') || str_starts_with(strtolower($ipAddress), 'fe80:');
    }

    public static function matchesCidr(string $ipAddress, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ipAddress === $cidr;
        }

        [$network, $prefixLength] = explode('/', $cidr, 2);
        $prefixLength = (int) $prefixLength;

        if (self::version($ipAddress) !== self::version($network)) {
            return false;
        }

        /** @var string $ipPacked */
        $ipPacked = inet_pton($ipAddress);
        /** @var string $networkPacked */
        $networkPacked = inet_pton($network);

        $bytesToCheck = intdiv($prefixLength, 8);
        $remainingBits = $prefixLength % 8;

        if ($bytesToCheck > 0 && substr($ipPacked, 0, $bytesToCheck) !== substr($networkPacked, 0, $bytesToCheck)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainingBits);

        return (ord($ipPacked[$bytesToCheck]) & $mask) === (ord($networkPacked[$bytesToCheck]) & $mask);
    }
}
