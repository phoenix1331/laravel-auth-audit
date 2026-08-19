<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies;

class InstanceBlindPolicy
{
    // no model param — instance-blind
    public function update(): bool
    {
        return true;
    }
}
