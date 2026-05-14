<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint;

use DateTimeImmutable;
use GlobusStudio\Fingerprint\Diagnostics\FingerprintDiagnostics;
use GlobusStudio\Fingerprint\Redaction\RedactorInterface;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSet;

final readonly class FingerprintResult
{
    /** @param array<string, mixed> $environment */
    public function __construct(
        private string $id,
        private string $version,
        private string $profile,
        private DateTimeImmutable $createdAt,
        private int $confidence,
        private int $entropyScore,
        private int $stabilityScore,
        private int $riskScore,
        private SignalSet $signals,
        private array $environment,
        private ?int $ttlSeconds = null,
        private FingerprintDiagnostics $diagnostics = new FingerprintDiagnostics(),
    ) {}

    public function id(): string
    {
        return $this->id;
    }

    public function version(): string
    {
        return $this->version;
    }

    public function profile(): string
    {
        return $this->profile;
    }

    public function createdAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function confidence(): int
    {
        return $this->confidence;
    }

    public function entropyScore(): int
    {
        return $this->entropyScore;
    }

    public function stabilityScore(): int
    {
        return $this->stabilityScore;
    }

    public function riskScore(): int
    {
        return $this->riskScore;
    }

    public function signals(): SignalSet
    {
        return $this->signals;
    }

    /** @return list<string> */
    public function usedSignalNames(): array
    {
        return $this->signals->names(true);
    }

    /** @return list<string> */
    public function ignoredSignalNames(): array
    {
        return array_map(static fn(Signal $signal): string => $signal->name(), $this->signals->ignored());
    }

    public function signalValue(string $signalName): mixed
    {
        return $this->signals->get($signalName)?->normalizedValue();
    }

    /** @return array<string, mixed> */
    public function environment(): array
    {
        return $this->environment;
    }

    public function diagnostics(): FingerprintDiagnostics
    {
        return $this->diagnostics;
    }

    public function ttlSeconds(): ?int
    {
        return $this->ttlSeconds;
    }

    public function expiresAt(): ?DateTimeImmutable
    {
        if ($this->ttlSeconds === null) {
            return null;
        }

        return $this->createdAt->modify('+' . $this->ttlSeconds . ' seconds') ?: null;
    }

    /** @return array<string, mixed> */
    public function toSafeArray(bool $allowRawValues = false, ?RedactorInterface $redactor = null): array
    {
        return [
            'id' => $this->id,
            'version' => $this->version,
            'profile' => $this->profile,
            'createdAt' => $this->createdAt->format(DATE_ATOM),
            'confidence' => $this->confidence,
            'entropyScore' => $this->entropyScore,
            'stabilityScore' => $this->stabilityScore,
            'riskScore' => $this->riskScore,
            'ttlSeconds' => $this->ttlSeconds,
            'expiresAt' => $this->expiresAt()?->format(DATE_ATOM),
            'usedSignalNames' => $this->usedSignalNames(),
            'ignoredSignalNames' => $this->ignoredSignalNames(),
            'environment' => $this->environment,
            'signals' => array_map(static fn(Signal $signal): array => $signal->toSafeArray($allowRawValues, $redactor), $this->signals->all()),
            'diagnostics' => $this->diagnostics->toArray(),
        ];
    }

    /** @return array<string, mixed> */
    public function toStorageArray(): array
    {
        return $this->toSafeArray(false);
    }

    /** @return array<string, mixed> */
    public function toExportArray(): array
    {
        return [
            'fingerprint' => $this->toSafeArray(false),
            'explanation' => array_map(
                static fn(Signal $signal): array => [
                    'name' => $signal->name(),
                    'type' => $signal->type()->value,
                    'included' => $signal->included(),
                    'reason' => $signal->reason(),
                    'stability' => $signal->stability()->value,
                    'sensitivity' => $signal->sensitivity()->value,
                    'source' => $signal->source(),
                ],
                $this->signals->all(),
            ),
        ];
    }
}
