<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint;

use DateTimeImmutable;
use GlobusStudio\Fingerprint\Collector\CookieSignalCollector;
use GlobusStudio\Fingerprint\Collector\FrameworkSignalCollector;
use GlobusStudio\Fingerprint\Collector\HeaderOrderSignalCollector;
use GlobusStudio\Fingerprint\Collector\HeaderSignalCollector;
use GlobusStudio\Fingerprint\Collector\NetworkSignalCollector;
use GlobusStudio\Fingerprint\Collector\ProxySignalCollector;
use GlobusStudio\Fingerprint\Collector\ServerSignalCollector;
use GlobusStudio\Fingerprint\Collector\SignalCollectorInterface;
use GlobusStudio\Fingerprint\Collector\TlsSignalCollector;
use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Diagnostics\FingerprintDiagnostics;
use GlobusStudio\Fingerprint\Hasher\CanonicalPayload;
use GlobusStudio\Fingerprint\Hasher\FingerprintHasherInterface;
use GlobusStudio\Fingerprint\Hasher\HmacSha256Hasher;
use GlobusStudio\Fingerprint\Request\NativeServerRequestFactory;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use Throwable;

final class FingerprintBuilder
{
    /** @param list<SignalCollectorInterface> $collectors */
    private function __construct(
        private FingerprintConfig $config,
        private RequestContext $request,
        private array $collectors,
        private FingerprintHasherInterface $hasher = new HmacSha256Hasher(),
        private ?object $logger = null,
    ) {}

    public static function fromGlobals(FingerprintConfig $config): self
    {
        return self::fromRequestContext(NativeServerRequestFactory::create(), $config);
    }

    public static function fromRequestContext(RequestContext $request, FingerprintConfig $config): self
    {
        return new self($config, $request, self::defaultCollectors());
    }

    /** @return list<SignalCollectorInterface> */
    public static function defaultCollectors(): array
    {
        return [
            new HeaderSignalCollector(),
            new NetworkSignalCollector(),
            new ProxySignalCollector(),
            new ServerSignalCollector(),
            new FrameworkSignalCollector(),
            new TlsSignalCollector(),
            new CookieSignalCollector(),
            new HeaderOrderSignalCollector(),
        ];
    }

    public function withCollector(SignalCollectorInterface $collector): self
    {
        $clone = clone $this;
        $clone->collectors[] = $collector;

        return $clone;
    }

    public function withHasher(FingerprintHasherInterface $hasher): self
    {
        $clone = clone $this;
        $clone->hasher = $hasher;

        return $clone;
    }

    public function withLogger(object $logger): self
    {
        $clone = clone $this;
        $clone->logger = $logger;

        return $clone;
    }

    public function build(): FingerprintResult
    {
        $signals = new SignalSet();
        $diagnostics = new FingerprintDiagnostics();

        foreach ($this->collectors as $collector) {
            try {
                $signals->merge($collector->collect($this->request, $this->config));
            } catch (Throwable $throwable) {
                $diagnostics->addUnavailableCollector($collector::class);
                $diagnostics->addWarning($throwable->getMessage());
                $this->log('warning', 'Fingerprint collector failed.', ['collector' => $collector::class, 'exception' => $throwable::class]);
            }
        }

        $payload = new CanonicalPayload([
            'algorithm' => $this->config->hashingConfig()->algorithmVersion(),
            'keyVersion' => $this->config->hashingConfig()->keyVersion(),
            'profile' => $this->config->privacyMode()->value,
            'signals' => $signals->toHashMap(),
        ]);

        $id = $this->hasher->hash($payload, $this->config->hashingConfig());

        return new FingerprintResult(
            $id,
            $this->config->hashingConfig()->algorithmVersion(),
            $this->config->privacyMode()->value,
            new DateTimeImmutable(),
            $this->confidenceScore($signals),
            $this->entropyScore($signals),
            $this->stabilityScore($signals),
            $this->riskScore($signals),
            $signals,
            $this->environment(),
            $this->config->ttlSeconds(),
            $diagnostics,
        );
    }

    /** @param array<string, mixed> $context */
    private function log(string $level, string $message, array $context = []): void
    {
        if ($this->logger === null) {
            return;
        }

        $logCallable = [$this->logger, 'log'];
        if (is_callable($logCallable)) {
            $logCallable($level, $message, $context);
            return;
        }

        $levelCallable = [$this->logger, $level];
        if (is_callable($levelCallable)) {
            $levelCallable($message, $context);
        }
    }

    private function confidenceScore(SignalSet $signals): int
    {
        $includedSignals = $signals->included();
        $availableWeight = array_sum(array_map(static fn(Signal $signal): int => max(0, $signal->weight()), $includedSignals));
        $expectedWeight = array_sum(FingerprintConfig::DEFAULT_WEIGHTS);

        if ($expectedWeight <= 0) {
            return 0;
        }

        $score = (int) round(($availableWeight / $expectedWeight) * 100);

        if ($signals->get('risk.untrusted_forwarded_header') !== null) {
            $score -= 10;
        }

        return max(0, min(100, $score));
    }

    private function entropyScore(SignalSet $signals): int
    {
        $score = 0;

        foreach ($signals->included() as $signal) {
            $score += max(1, $signal->weight()) * match ($signal->reliability()) {
                'high' => 2,
                'low' => 1,
                default => 1,
            };
        }

        return min(100, $score * 2);
    }

    private function stabilityScore(SignalSet $signals): int
    {
        $includedSignals = $signals->included();

        if ($includedSignals === []) {
            return 0;
        }

        $weightedTotal = 0;
        $weightTotal = 0;

        foreach ($includedSignals as $signal) {
            $weight = max(1, $signal->weight());
            $weightedTotal += $signal->stability()->score() * $weight;
            $weightTotal += $weight;
        }

        return (int) round($weightedTotal / max(1, $weightTotal));
    }

    private function riskScore(SignalSet $signals): int
    {
        $score = 0;
        $botLikelihood = $signals->get('bot.likelihood')?->normalizedValue();

        if (is_int($botLikelihood) && $botLikelihood >= 80) {
            $score += 30;
        }

        if ($signals->get('risk.untrusted_forwarded_header') !== null) {
            $score += 25;
        }

        if ($signals->get('proxy.headers_present')?->normalizedValue() === true) {
            $score += 10;
        }

        if ($signals->get('header.accept_language') === null && $signals->get('browser.family') !== null) {
            $score += 5;
        }

        return min(100, $score);
    }

    /** @return array<string, mixed> */
    private function environment(): array
    {
        return [
            'sapi' => $this->request->sapi(),
            'serverProtocol' => $this->request->protocol(),
            'method' => $this->request->method(),
            'https' => $this->request->server()->string('HTTPS') !== '',
            'serverSoftware' => $this->request->server()->string('SERVER_SOFTWARE', 'unknown'),
        ];
    }
}
