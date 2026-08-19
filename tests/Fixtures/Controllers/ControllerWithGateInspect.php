<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Support\Facades\Gate;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithGateInspect
{
    public function update(Order $order): void
    {
        $response = Gate::inspect('update', $order);

        if ($response->denied()) {
            abort(403, $response->message());
        }
    }
}
