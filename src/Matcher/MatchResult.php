<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Matcher;

final readonly class MatchResult
{
    /**
     * @param list<string> $changedSignals
     * @param list<string> $riskReasons
     */
    public function __construct(
        private MatchLevel $level,
        private int $distance,
        private bool $exactMatch,
        private int $stableSignalsMatched,
        private int $volatileSignalsChanged,
        private array $changedSignals,
        private array $riskReasons,
    ) {}

    public function level(): MatchLevel
    {
        return $this->level;
    }

    public function distance(): int
    {
        return $this->distance;
    }

    public function exactMatch(): bool
    {
        return $this->exactMatch;
    }

    public function partialMatch(): bool
    {
        return !$this->exactMatch && $this->distance < 50;
    }

    public function stableSignalsMatched(): int
    {
        return $this->stableSignalsMatched;
    }

    public function volatileSignalsChanged(): int
    {
        return $this->volatileSignalsChanged;
    }

    /** @return list<string> */
    public function changedSignals(): array
    {
        return $this->changedSignals;
    }

    /** @return list<string> */
    public function riskReasons(): array
    {
        /** @var list<string> $riskReasons */
        $riskReasons = $this->riskReasons;

        return $riskReasons;
    }
}
