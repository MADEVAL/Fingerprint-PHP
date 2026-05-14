<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Signal;

final class SignalSet
{
    /** @var array<string, Signal> */
    private array $signals = [];

    /** @param iterable<Signal> $signals */
    public function __construct(iterable $signals = [])
    {
        foreach ($signals as $signal) {
            $this->add($signal);
        }
    }

    public function add(Signal $signal): void
    {
        $this->signals[$signal->name()] = $signal;
    }

    public function merge(self $other): void
    {
        foreach ($other->all() as $signal) {
            $this->add($signal);
        }
    }

    public function get(string $name): ?Signal
    {
        return $this->signals[$name] ?? null;
    }

    /** @return list<Signal> */
    public function all(): array
    {
        return array_values($this->signals);
    }

    /** @return list<Signal> */
    public function included(): array
    {
        return array_values(array_filter($this->signals, static fn(Signal $signal): bool => $signal->included()));
    }

    /** @return list<Signal> */
    public function ignored(): array
    {
        return array_values(array_filter($this->signals, static fn(Signal $signal): bool => !$signal->included()));
    }

    /** @return array<string, mixed> */
    public function toHashMap(): array
    {
        $hashMap = [];

        foreach ($this->included() as $signal) {
            $hashMap[$signal->name()] = $signal->normalizedValue();
        }

        ksort($hashMap);

        return $hashMap;
    }

    /** @return list<string> */
    public function names(bool $includedOnly = false): array
    {
        $signals = $includedOnly ? $this->included() : $this->all();

        return array_map(static fn(Signal $signal): string => $signal->name(), $signals);
    }

    public function count(): int
    {
        return count($this->signals);
    }
}
