<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Redaction;

use GlobusStudio\Fingerprint\Signal\SignalSensitivity;

final class DefaultRedactor implements RedactorInterface
{
    public function redact(mixed $value, SignalSensitivity $sensitivity): mixed
    {
        return match ($sensitivity) {
            SignalSensitivity::Low => $value,
            SignalSensitivity::Medium => is_string($value) ? substr($value, 0, 120) : $value,
            SignalSensitivity::High => '[hashed]',
            SignalSensitivity::Special => '[omitted]',
        };
    }
}
