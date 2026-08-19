<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Support\Facades\Gate;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithDiscardedGateResult
{
    public function update(Order $order): void
    {
        // result discarded — no conditional, assignment, or return
        Gate::allows('update', $order);
    }
}
