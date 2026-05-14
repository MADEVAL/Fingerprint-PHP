<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Redaction;

use GlobusStudio\Fingerprint\Signal\SignalSensitivity;

interface RedactorInterface
{
    public function redact(mixed $value, SignalSensitivity $sensitivity): mixed;
}
