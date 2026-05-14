<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Signal;

use GlobusStudio\Fingerprint\Redaction\DefaultRedactor;
use GlobusStudio\Fingerprint\Redaction\RedactorInterface;

final readonly class Signal
{
    public function __construct(
        private string $name,
        private SignalType $type,
        private mixed $rawValue,
        private mixed $normalizedValue,
        private int $weight,
        private SignalStability $stability,
        private SignalSensitivity $sensitivity,
        private string $source,
        private bool $included = true,
        private string $reason = 'included',
        private string $reliability = 'medium',
    ) {}

    public function name(): string
    {
        return $this->name;
    }

    public function type(): SignalType
    {
        return $this->type;
    }

    public function rawValue(): mixed
    {
        return $this->rawValue;
    }

    public function normalizedValue(): mixed
    {
        return $this->normalizedValue;
    }

    public function hashedValue(): string
    {
        return hash('sha256', json_encode($this->normalizedValue, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public function weight(): int
    {
        return $this->weight;
    }

    public function stability(): SignalStability
    {
        return $this->stability;
    }

    public function sensitivity(): SignalSensitivity
    {
        return $this->sensitivity;
    }

    public function source(): string
    {
        return $this->source;
    }

    public function included(): bool
    {
        return $this->included;
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function reliability(): string
    {
        return $this->reliability;
    }

    /** @return array<string, mixed> */
    public function toSafeArray(bool $allowRawValue = false, ?RedactorInterface $redactor = null): array
    {
        $redactor ??= new DefaultRedactor();

        $data = [
            'name' => $this->name,
            'type' => $this->type->value,
            'normalizedValue' => $redactor->redact($this->normalizedValue, $this->sensitivity),
            'hashedValue' => $this->hashedValue(),
            'weight' => $this->weight,
            'stability' => $this->stability->value,
            'sensitivity' => $this->sensitivity->value,
            'source' => $this->source,
            'included' => $this->included,
            'reason' => $this->reason,
            'reliability' => $this->reliability,
        ];

        if ($allowRawValue && $this->sensitivity !== SignalSensitivity::Special) {
            $data['rawValue'] = $this->rawValue;
        }

        return $data;
    }
}
