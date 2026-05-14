<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Collector;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Signal\SignalStability;
use GlobusStudio\Fingerprint\Signal\SignalType;

final class HeaderOrderSignalCollector implements SignalCollectorInterface
{
    /** @var list<string> */
    private const EXCLUDED_FROM_ORDER = ['host', 'content-length', 'content-type', 'cookie', 'authorization', 'x-request-id', 'traceparent', 'tracestate'];

    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();

        if (!$config->shouldIncludeHeaderOrder()) {
            return $signals;
        }

        $sequence = array_values(array_filter(
            $request->headers()->order(),
            static fn(string $headerName): bool => !in_array($headerName, self::EXCLUDED_FROM_ORDER, true) && !$config->isHeaderDenied($headerName),
        ));

        if ($sequence === []) {
            return $signals;
        }

        $hash = hash('sha256', implode('|', $sequence));
        $reliability = in_array($request->sapi(), ['fpm-fcgi', 'cgi-fcgi', 'cgi'], true) ? 'low' : 'medium';

        $signals->add(new Signal('header.order_hash', SignalType::Header, $sequence, $hash, $config->weightFor('header.order_hash'), SignalStability::Medium, SignalSensitivity::Low, 'headers.order', true, 'included', $reliability));

        return $signals;
    }
}
