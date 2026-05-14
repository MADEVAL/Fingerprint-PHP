<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Signal;

enum SignalStability: string
{
    case Volatile = 'volatile';
    case Medium = 'medium';
    case Stable = 'stable';

    public function score(): int
    {
        return match ($this) {
            self::Volatile => 25,
            self::Medium => 60,
            self::Stable => 90,
        };
    }
}
