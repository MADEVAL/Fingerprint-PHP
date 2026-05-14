<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Configuration;

enum PrivacyMode: string
{
    case Strict = 'strict';
    case Balanced = 'balanced';
    case Maximum = 'maximum';
    case Custom = 'custom';
}
