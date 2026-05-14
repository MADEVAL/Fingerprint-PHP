<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Collector;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\SignalSet;

interface SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet;
}
