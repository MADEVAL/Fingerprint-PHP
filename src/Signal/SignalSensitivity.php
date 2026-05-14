<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Signal;

enum SignalSensitivity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Special = 'special';
}
