<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Storage;

use GlobusStudio\Fingerprint\FingerprintResult;

interface FingerprintStorageInterface
{
    public function save(string $subjectId, FingerprintResult $result): void;

    public function findLatestBySubject(string $subjectId): ?FingerprintResult;

    /** @return list<FingerprintResult> */
    public function findBySubject(string $subjectId, int $limit = 10): array;

    public function deleteBySubject(string $subjectId): void;
}
