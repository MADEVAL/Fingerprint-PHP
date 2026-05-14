<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Matcher;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\FingerprintResult;
use GlobusStudio\Fingerprint\Signal\SignalStability;

final readonly class FingerprintMatcher
{
    /** @param array<string, int> $weights */
    public function __construct(private array $weights = FingerprintConfig::DEFAULT_WEIGHTS) {}

    public function compare(FingerprintResult $current, FingerprintResult $known): MatchResult
    {
        if (hash_equals($known->id(), $current->id())) {
            return new MatchResult(MatchLevel::Same, 0, true, count($current->signals()->included()), 0, [], []);
        }

        $currentSignals = $current->signals()->toHashMap();
        $knownSignals = $known->signals()->toHashMap();
        $signalNames = array_values(array_unique([...array_keys($currentSignals), ...array_keys($knownSignals)]));

        if ($signalNames === []) {
            return new MatchResult(MatchLevel::Unknown, 100, false, 0, 0, [], ['no_comparable_signals']);
        }

        $changedSignals = [];
        $changedWeight = 0;
        $totalWeight = 0;
        $stableSignalsMatched = 0;
        $volatileSignalsChanged = 0;

        foreach ($signalNames as $signalName) {
            $weight = $this->weights[$signalName] ?? 1;
            $totalWeight += $weight;

            if (($currentSignals[$signalName] ?? null) !== ($knownSignals[$signalName] ?? null)) {
                $changedSignals[] = $signalName;
                $changedWeight += $weight;

                if ($current->signals()->get($signalName)?->stability() === SignalStability::Volatile) {
                    ++$volatileSignalsChanged;
                }
            } elseif ($current->signals()->get($signalName)?->stability() === SignalStability::Stable) {
                ++$stableSignalsMatched;
            }
        }

        $distance = (int) round(($changedWeight / max(1, $totalWeight)) * 100);
        $riskReasons = $this->riskReasons($current, $known, $changedSignals, $distance);
        $level = $this->level($distance, $riskReasons);

        return new MatchResult($level, $distance, false, $stableSignalsMatched, $volatileSignalsChanged, $changedSignals, $riskReasons);
    }

    /**
     * @param list<string> $changedSignals
     * @return list<string>
     */
    private function riskReasons(FingerprintResult $current, FingerprintResult $known, array $changedSignals, int $distance): array
    {
        /** @var list<string> $reasons */
        $reasons = [];
        $stableIdentitySignals = ['browser.family', 'os.family', 'device.class', 'header.accept_language'];

        foreach ($stableIdentitySignals as $stableSignal) {
            if (in_array($stableSignal, $changedSignals, true)) {
                $reasons[] = $stableSignal . '_changed';
            }
        }

        if ($known->signalValue('proxy.chain_shape') === null && $current->signalValue('proxy.chain_shape') !== null) {
            $reasons[] = 'proxy_chain_appeared';
        }

        if ($current->riskScore() >= 40) {
            $reasons[] = 'current_risk_score_high';
        }

        if ($distance >= 65) {
            $reasons[] = 'large_fingerprint_distance';
        }

        /** @var list<string> $uniqueReasons */
        $uniqueReasons = array_values(array_unique($reasons));

        return $uniqueReasons;
    }

    /** @param list<string> $riskReasons */
    private function level(int $distance, array $riskReasons): MatchLevel
    {
        if ($riskReasons !== [] && $distance >= 30) {
            return MatchLevel::Suspicious;
        }

        if ($distance <= 20) {
            return MatchLevel::Similar;
        }

        if ($distance <= 50) {
            return MatchLevel::Changed;
        }

        return MatchLevel::Suspicious;
    }
}
