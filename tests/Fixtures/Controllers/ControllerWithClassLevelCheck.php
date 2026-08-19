<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithClassLevelCheck
{
    public function update(Order $order): void
    {
        $this->authorize('update', Order::class);
    }
}
