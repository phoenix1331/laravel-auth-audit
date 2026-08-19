<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Http\Request;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithAbortUnlessCan
{
    public function update(Request $request, Order $order): void
    {
        abort_unless($request->user()->can('update', $order), 403);
    }

    public function destroy(Request $request, Order $order): void
    {
        abort_if(! $request->user()->can('delete', $order), 403);
    }
}
