<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Support\Facades\Gate;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithUsedGateResult
{
    public function update(Order $order): void
    {
        if (Gate::allows('update', $order)) {
            // proceed
        }
    }

    public function destroy(Order $order): void
    {
        abort_unless(Gate::allows('delete', $order), 403);
    }
}
