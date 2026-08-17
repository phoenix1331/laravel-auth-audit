<?php

namespace Phoenix1331\LaravelAuthAudit\Data;

class AuditReport
{
    /** @param RouteEntry[] $routes */
    public function __construct(
        public readonly array $routes,
        public readonly int $totalRoutes,
        public readonly int $authorisedCount,
        public readonly int $unauthorisedCount,
        public readonly int $skippedCount,
        public readonly int $excludedCount,
        public readonly float $coveragePercentage,
        public readonly ?int $previousSkippedCount = null,
        public readonly ?float $previousCoveragePercentage = null,
    ) {}

    public function skippedDelta(): ?int
    {
        if ($this->previousSkippedCount === null) {
            return null;
        }

        return $this->skippedCount - $this->previousSkippedCount;
    }

    public function coverageDelta(): ?float
    {
        if ($this->previousCoveragePercentage === null) {
            return null;
        }

        return $this->coveragePercentage - $this->previousCoveragePercentage;
    }
}
