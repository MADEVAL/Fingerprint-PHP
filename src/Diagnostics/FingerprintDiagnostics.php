<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Diagnostics;

final class FingerprintDiagnostics
{
    /** @var list<string> */
    private array $warnings = [];

    /** @var list<string> */
    private array $unavailableCollectors = [];

    public function addWarning(string $warning): void
    {
        $this->warnings[] = $warning;
    }

    public function addUnavailableCollector(string $collector): void
    {
        $this->unavailableCollectors[] = $collector;
    }

    /** @return list<string> */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /** @return list<string> */
    public function unavailableCollectors(): array
    {
        return $this->unavailableCollectors;
    }

    /** @return array<string, list<string>> */
    public function toArray(): array
    {
        return [
            'warnings' => $this->warnings,
            'unavailableCollectors' => $this->unavailableCollectors,
        ];
    }
}
