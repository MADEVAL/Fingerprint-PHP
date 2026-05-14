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

final class ProxySignalCollector implements SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();
        $proxyHeaders = $this->proxyHeaders($request);
        $chainLength = $this->chainLength($request);
        $cdnProvider = $this->cdnProvider($request);
        $remoteIsTrusted = $config->trustedProxiesConfig()->isTrusted($request->remoteAddress());

        $signals->add(new Signal('proxy.headers_present', SignalType::Proxy, $proxyHeaders, $proxyHeaders !== [], 0, SignalStability::Volatile, SignalSensitivity::Low, 'proxy.headers', false, 'context_only'));
        $signals->add(new Signal('proxy.chain_length', SignalType::Proxy, $request->headers()->get('x-forwarded-for'), $chainLength, 0, SignalStability::Volatile, SignalSensitivity::Low, 'header.x-forwarded-for', false, 'context_only'));

        if ($proxyHeaders !== []) {
            $shape = sprintf('headers:%s|chain:%d|trusted:%s|cdn:%s', implode(',', $proxyHeaders), $chainLength, $remoteIsTrusted ? 'yes' : 'no', $cdnProvider ?? 'none');
            $signals->add(new Signal('proxy.chain_shape', SignalType::Proxy, $shape, $shape, $config->weightFor('proxy.chain_shape'), SignalStability::Medium, SignalSensitivity::Low, 'proxy.headers', $remoteIsTrusted, $remoteIsTrusted ? 'included' : 'untrusted_proxy_context'));
        }

        if ($proxyHeaders !== [] && !$remoteIsTrusted) {
            $signals->add(new Signal('risk.untrusted_forwarded_header', SignalType::Proxy, $proxyHeaders, true, 0, SignalStability::Volatile, SignalSensitivity::Low, 'proxy.headers', false, 'risk_only'));
        }

        if ($cdnProvider !== null) {
            $signals->add(new Signal('risk.cdn_provider', SignalType::Proxy, $cdnProvider, $cdnProvider, 0, SignalStability::Medium, SignalSensitivity::Low, 'cdn.headers', false, 'risk_only'));
        }

        return $signals;
    }

    /** @return list<string> */
    private function proxyHeaders(RequestContext $request): array
    {
        $headers = [];

        foreach (['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip', 'via', 'cf-connecting-ip', 'true-client-ip', 'fastly-client-ip', 'cdn-loop'] as $headerName) {
            if ($request->headers()->has($headerName)) {
                $headers[] = $headerName;
            }
        }

        return $headers;
    }

    private function chainLength(RequestContext $request): int
    {
        $forwardedFor = $request->headers()->get('x-forwarded-for');

        if ($forwardedFor === null || trim($forwardedFor) === '') {
            return 0;
        }

        return count(array_filter(array_map('trim', explode(',', $forwardedFor)), static fn(string $value): bool => $value !== ''));
    }

    private function cdnProvider(RequestContext $request): ?string
    {
        return match (true) {
            $request->headers()->has('cf-ray') || $request->headers()->has('cf-connecting-ip') => 'cloudflare',
            $request->headers()->has('fastly-client-ip') => 'fastly',
            $request->headers()->has('x-akamai-edgescape') => 'akamai',
            default => null,
        };
    }
}
