<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Signal;

enum SignalType: string
{
    case Header = 'header';
    case Network = 'network';
    case Tls = 'tls';
    case Cookie = 'cookie';
    case Server = 'server';
    case Proxy = 'proxy';
    case Framework = 'framework';
    case Derived = 'derived';
}
