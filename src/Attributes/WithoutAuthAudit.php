<?php

namespace Phoenix1331\LaravelAuthAudit\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class WithoutAuthAudit
{
    public function __construct(
        public readonly string $reason,
        public readonly ?string $expires = null,
    ) {}

    public function isExpired(): bool
    {
        if ($this->expires === null) {
            return false;
        }

        return strtotime($this->expires) < time();
    }
}
