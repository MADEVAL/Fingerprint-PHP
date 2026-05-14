<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Storage;

use GlobusStudio\Fingerprint\FingerprintResult;

final class InMemoryFingerprintStorage implements FingerprintStorageInterface
{
    /** @var array<string, list<FingerprintResult>> */
    private array $items = [];

    public function save(string $subjectId, FingerprintResult $result): void
    {
        $this->items[$subjectId] ??= [];
        array_unshift($this->items[$subjectId], $result);
    }

    public function findLatestBySubject(string $subjectId): ?FingerprintResult
    {
        return $this->items[$subjectId][0] ?? null;
    }

    public function findBySubject(string $subjectId, int $limit = 10): array
    {
        return array_slice($this->items[$subjectId] ?? [], 0, $limit);
    }

    public function deleteBySubject(string $subjectId): void
    {
        unset($this->items[$subjectId]);
    }
}
