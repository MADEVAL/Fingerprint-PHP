<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Tests\Support {
    final class SodiumFunctionAvailability
    {
        public static ?bool $available = null;
    }
}

namespace GlobusStudio\Fingerprint\Hasher {
    function function_exists(string $function): bool
    {
        return \GlobusStudio\Fingerprint\Tests\Support\SodiumFunctionAvailability::$available ?? \function_exists($function);
    }
}
