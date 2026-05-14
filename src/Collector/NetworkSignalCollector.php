<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Collector;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Normalizer\IpNormalizer;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Signal\SignalStability;
use GlobusStudio\Fingerprint\Signal\SignalType;

final class NetworkSignalCollector implements SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();
        $remoteAddress = $request->remoteAddress();
        $resolvedClientIp = $this->resolveClientIp($request, $config);
        $clientIp = $resolvedClientIp ?? $remoteAddress;

        if (!IpNormalizer::isValid($clientIp)) {
            $signals->add(new Signal('ip.invalid', SignalType::Network, $clientIp, 'invalid', 0, SignalStability::Volatile, SignalSensitivity::Low, 'network.client_ip', false, 'invalid_ip'));
            return $signals;
        }

        $signals->add(new Signal('remote_addr', SignalType::Network, $remoteAddress, IpNormalizer::isValid($remoteAddress) ? IpNormalizer::prefix($remoteAddress) : 'invalid', 0, SignalStability::Volatile, SignalSensitivity::High, 'server.REMOTE_ADDR', false, 'diagnostic_only'));
        $signals->add(new Signal('ip.version', SignalType::Network, $clientIp, IpNormalizer::version($clientIp), 1, SignalStability::Medium, SignalSensitivity::Low, 'network.client_ip'));

        $prefix = IpNormalizer::prefix($clientIp, $config->ipPrefixingConfig()->ipv4PrefixLength(), $config->ipPrefixingConfig()->ipv6PrefixLength());
        if ($prefix !== null) {
            $signals->add(new Signal('ip.prefix', SignalType::Network, $clientIp, $prefix, $config->weightFor('ip.prefix'), SignalStability::Medium, SignalSensitivity::High, 'network.client_ip'));
        }

        if ($config->ipPrefixingConfig()->allowFullIpAddress()) {
            $signals->add(new Signal('ip.full', SignalType::Network, $clientIp, $clientIp, $config->weightFor('ip.full'), SignalStability::Volatile, SignalSensitivity::High, 'network.client_ip'));
        }

        $signals->add(new Signal('ip.is_private', SignalType::Network, $clientIp, IpNormalizer::isPrivate($clientIp), 0, SignalStability::Medium, SignalSensitivity::Low, 'network.client_ip', false, 'context_only'));
        $signals->add(new Signal('ip.is_reserved', SignalType::Network, $clientIp, IpNormalizer::isReserved($clientIp), 0, SignalStability::Medium, SignalSensitivity::Low, 'network.client_ip', false, 'context_only'));
        $signals->add(new Signal('ip.is_loopback', SignalType::Network, $clientIp, IpNormalizer::isLoopback($clientIp), 0, SignalStability::Medium, SignalSensitivity::Low, 'network.client_ip', false, 'context_only'));
        $signals->add(new Signal('ip.is_link_local', SignalType::Network, $clientIp, IpNormalizer::isLinkLocal($clientIp), 0, SignalStability::Medium, SignalSensitivity::Low, 'network.client_ip', false, 'context_only'));
        $signals->add(new Signal('ip.proxy_header_present', SignalType::Network, $clientIp, $this->forwardedHeaderPresent($request), 0, SignalStability::Volatile, SignalSensitivity::Low, 'proxy.headers', false, 'context_only'));
        $signals->add(new Signal('trusted_proxy.match', SignalType::Network, $remoteAddress, $config->trustedProxiesConfig()->isTrusted($remoteAddress), 0, SignalStability::Volatile, SignalSensitivity::Low, 'server.REMOTE_ADDR', false, 'context_only'));

        return $signals;
    }

    private function resolveClientIp(RequestContext $request, FingerprintConfig $config): ?string
    {
        $remoteAddress = $request->remoteAddress();

        if (!$config->trustedProxiesConfig()->isTrusted($remoteAddress)) {
            return IpNormalizer::isValid($remoteAddress) ? $remoteAddress : null;
        }

        if ($config->trustedProxiesConfig()->trustsHeader('cf-connecting-ip')) {
            $cloudflareIp = $request->headers()->get('cf-connecting-ip');
            if ($cloudflareIp !== null && IpNormalizer::isValid($cloudflareIp)) {
                return $cloudflareIp;
            }
        }

        if ($config->trustedProxiesConfig()->trustsHeader('true-client-ip')) {
            $trueClientIp = $request->headers()->get('true-client-ip');
            if ($trueClientIp !== null && IpNormalizer::isValid($trueClientIp)) {
                return $trueClientIp;
            }
        }

        if ($config->trustedProxiesConfig()->trustsHeader('x-real-ip')) {
            $realIp = $request->headers()->get('x-real-ip');
            if ($realIp !== null && IpNormalizer::isValid($realIp)) {
                return $realIp;
            }
        }

        if (!$config->trustedProxiesConfig()->trustsHeader('x-forwarded-for')) {
            return IpNormalizer::isValid($remoteAddress) ? $remoteAddress : null;
        }

        $chain = $this->parseIpChain($request->headers()->get('x-forwarded-for') ?? '');

        for ($index = count($chain) - 1; $index >= 0; --$index) {
            $candidateIp = $chain[$index];

            if (!$config->trustedProxiesConfig()->isTrusted($candidateIp)) {
                return $candidateIp;
            }
        }

        return $chain[0] ?? (IpNormalizer::isValid($remoteAddress) ? $remoteAddress : null);
    }

    /** @return list<string> */
    private function parseIpChain(string $headerValue): array
    {
        $chain = [];

        foreach (explode(',', $headerValue) as $candidate) {
            $candidateIp = trim($candidate);

            if (IpNormalizer::isValid($candidateIp)) {
                $chain[] = $candidateIp;
            }
        }

        return $chain;
    }

    private function forwardedHeaderPresent(RequestContext $request): bool
    {
        foreach (['forwarded', 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'true-client-ip', 'fastly-client-ip'] as $headerName) {
            if ($request->headers()->has($headerName)) {
                return true;
            }
        }

        return false;
    }
}
