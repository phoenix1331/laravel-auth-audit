<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Support\Facades\Gate;

class ControllerWithGateAuthorize
{
    public function destroy($invoice): void
    {
        Gate::authorize('delete', $invoice);
    }
}
