<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Support\Facades\Gate;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithGateClassLevelCheck
{
    public function update(Order $order): void
    {
        Gate::authorize('update', Order::class);
    }
}
