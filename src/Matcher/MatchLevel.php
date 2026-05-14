<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Matcher;

enum MatchLevel: string
{
    case Same = 'same';
    case Similar = 'similar';
    case Changed = 'changed';
    case Suspicious = 'suspicious';
    case Unknown = 'unknown';

    public function isSuspicious(): bool
    {
        return $this === self::Suspicious;
    }
}
