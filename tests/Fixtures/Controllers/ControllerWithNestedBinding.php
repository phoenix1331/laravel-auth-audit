<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Team;

class ControllerWithNestedBinding
{
    public function show(Team $team, Order $order): void
    {
        $this->authorize('view', $order);
    }
}
