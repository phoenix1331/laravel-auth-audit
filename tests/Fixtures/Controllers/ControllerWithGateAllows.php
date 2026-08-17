<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Support\Facades\Gate;

class ControllerWithGateAllows
{
    public function export(): void
    {
        if (Gate::allows('view-reports')) {
            // proceed
        }
    }
}
