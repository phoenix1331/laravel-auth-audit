<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies;

class OrderPolicy
{
    public function view(): bool
    {
        return true;
    }

    public function update(): bool
    {
        return true;
    }

    public function delete(): bool
    {
        return true;
    }
}
