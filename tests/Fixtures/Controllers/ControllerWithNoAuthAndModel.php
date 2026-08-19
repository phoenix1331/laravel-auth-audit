<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithNoAuthAndModel
{
    public function update(Order $order): void
    {
        // no authorisation check — falls through to tier 3 policy detection
    }
}
