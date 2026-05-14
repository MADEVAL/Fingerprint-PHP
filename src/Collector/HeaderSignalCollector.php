<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Collector;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Normalizer\AcceptLanguageNormalizer;
use GlobusStudio\Fingerprint\Normalizer\EncodingNormalizer;
use GlobusStudio\Fingerprint\Normalizer\HeaderNormalizer;
use GlobusStudio\Fingerprint\Normalizer\UserAgentNormalizer;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Signal\SignalStability;
use GlobusStudio\Fingerprint\Signal\SignalType;

final readonly class HeaderSignalCollector implements SignalCollectorInterface
{
    public function __construct(
        private UserAgentNormalizer $userAgentNormalizer = new UserAgentNormalizer(),
        private AcceptLanguageNormalizer $acceptLanguageNormalizer = new AcceptLanguageNormalizer(),
        private EncodingNormalizer $encodingNormalizer = new EncodingNormalizer(),
    ) {}

    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();
        $headers = $request->headers()->all();

        if (count($headers) > $config->maxHeaderCount()) {
            $signals->add(new Signal('header.limit_exceeded', SignalType::Header, count($headers), 'too_many_headers', 0, SignalStability::Volatile, SignalSensitivity::Low, 'headers', false, 'max_header_count_exceeded'));
        }

        $tooLongHeaders = [];
        foreach ($headers as $headerName => $headerValue) {
            if (strlen($headerValue) > $config->maxHeaderLength()) {
                $tooLongHeaders[] = $headerName;
            }
        }

        if ($tooLongHeaders !== []) {
            $signals->add(new Signal('header.length_exceeded', SignalType::Header, $tooLongHeaders, $tooLongHeaders, 0, SignalStability::Volatile, SignalSensitivity::Low, 'headers', false, 'max_header_length_exceeded'));
        }

        $this->collectUserAgent($signals, $request, $config);
        $this->collectAcceptHeaders($signals, $request, $config);
        $this->collectClientHints($signals, $request, $config);
        $this->collectFetchMetadata($signals, $request, $config);

        return $signals;
    }

    private function collectUserAgent(SignalSet $signals, RequestContext $request, FingerprintConfig $config): void
    {
        $userAgent = $request->headers()->get('user-agent');

        if ($userAgent === null || $this->tooLong($userAgent, $config)) {
            return;
        }

        $normalizedUserAgent = $this->userAgentNormalizer->normalize($userAgent);
        $this->add($signals, $config, 'header.user_agent', SignalType::Header, $userAgent, $normalizedUserAgent, 2, SignalStability::Medium, SignalSensitivity::Medium, 'header.user-agent');

        foreach ($this->userAgentNormalizer->profile($userAgent) as $signalName => $value) {
            $included = $signalName !== 'bot.likelihood';
            $this->add($signals, $config, $signalName, SignalType::Derived, $userAgent, $value, $config->weightFor($signalName, 1), SignalStability::Medium, SignalSensitivity::Low, 'header.user-agent', $included, $included ? 'included' : 'risk_only');
        }
    }

    private function collectAcceptHeaders(SignalSet $signals, RequestContext $request, FingerprintConfig $config): void
    {
        $accept = $request->headers()->get('accept');
        if ($accept !== null && !$this->tooLong($accept, $config)) {
            $this->add($signals, $config, 'header.accept', SignalType::Header, $accept, HeaderNormalizer::normalizeAccept($accept), $config->weightFor('header.accept'), SignalStability::Medium, SignalSensitivity::Low, 'header.accept');
        }

        $acceptLanguage = $request->headers()->get('accept-language');
        if ($acceptLanguage !== null && !$this->tooLong($acceptLanguage, $config)) {
            $this->add($signals, $config, 'header.accept_language', SignalType::Header, $acceptLanguage, $this->acceptLanguageNormalizer->normalize($acceptLanguage), $config->weightFor('header.accept_language'), SignalStability::Stable, SignalSensitivity::Medium, 'header.accept-language');
        }

        $acceptEncoding = $request->headers()->get('accept-encoding');
        if ($acceptEncoding !== null && !$this->tooLong($acceptEncoding, $config)) {
            $this->add($signals, $config, 'header.accept_encoding', SignalType::Header, $acceptEncoding, $this->encodingNormalizer->normalize($acceptEncoding), $config->weightFor('header.accept_encoding'), SignalStability::Medium, SignalSensitivity::Low, 'header.accept-encoding');
        }

        $acceptCharset = $request->headers()->get('accept-charset');
        if ($acceptCharset !== null && !$this->tooLong($acceptCharset, $config)) {
            $this->add($signals, $config, 'header.accept_charset', SignalType::Header, $acceptCharset, HeaderNormalizer::normalizeCommaSeparatedQValues($acceptCharset), 1, SignalStability::Stable, SignalSensitivity::Low, 'header.accept-charset');
        }
    }

    private function collectClientHints(SignalSet $signals, RequestContext $request, FingerprintConfig $config): void
    {
        if (!$config->shouldIncludeClientHints()) {
            return;
        }

        $mapping = [
            'sec-ch-ua' => 'client_hints.brands',
            'sec-ch-ua-mobile' => 'client_hints.mobile',
            'sec-ch-ua-platform' => 'client_hints.platform',
            'sec-ch-ua-platform-version' => 'client_hints.platform_version',
            'sec-ch-ua-arch' => 'client_hints.arch',
            'sec-ch-ua-bitness' => 'client_hints.bitness',
            'sec-ch-ua-full-version' => 'client_hints.full_version',
            'sec-ch-ua-full-version-list' => 'client_hints.full_version_list',
            'sec-ch-ua-model' => 'client_hints.model',
            'sec-ch-ua-wow64' => 'client_hints.wow64',
        ];

        foreach ($mapping as $headerName => $signalName) {
            $value = $request->headers()->get($headerName);

            if ($value === null || $this->tooLong($value, $config)) {
                continue;
            }

            $normalizedValue = trim(HeaderNormalizer::normalizeValue($value), '"');
            $sensitivity = in_array($headerName, ['sec-ch-ua-full-version', 'sec-ch-ua-full-version-list', 'sec-ch-ua-model'], true) ? SignalSensitivity::Medium : SignalSensitivity::Low;
            $stability = str_contains($signalName, 'full_version') ? SignalStability::Volatile : SignalStability::Medium;
            $this->add($signals, $config, $signalName, SignalType::Header, $value, $normalizedValue, $config->weightFor($signalName, 2), $stability, $sensitivity, 'header.' . $headerName);
        }
    }

    private function collectFetchMetadata(SignalSet $signals, RequestContext $request, FingerprintConfig $config): void
    {
        foreach (['dnt', 'sec-gpc', 'upgrade-insecure-requests', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user'] as $headerName) {
            $value = $request->headers()->get($headerName);

            if ($value === null || $this->tooLong($value, $config)) {
                continue;
            }

            $this->add($signals, $config, 'header.' . str_replace('-', '_', $headerName), SignalType::Header, $value, strtolower(HeaderNormalizer::normalizeValue($value)), 1, SignalStability::Volatile, SignalSensitivity::Low, 'header.' . $headerName, false, 'context_only');
        }
    }

    private function add(SignalSet $signals, FingerprintConfig $config, string $name, SignalType $type, mixed $rawValue, mixed $normalizedValue, int $weight, SignalStability $stability, SignalSensitivity $sensitivity, string $source, bool $included = true, string $reason = 'included'): void
    {
        $effectiveIncluded = $included && !$config->isSignalDisabled($name);
        $signals->add(new Signal($name, $type, $rawValue, $normalizedValue, $weight, $stability, $sensitivity, $source, $effectiveIncluded, $effectiveIncluded ? $reason : 'disabled'));
    }

    private function tooLong(string $value, FingerprintConfig $config): bool
    {
        return strlen($value) > $config->maxHeaderLength();
    }
}
