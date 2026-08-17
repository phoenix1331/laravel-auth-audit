<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests\BareFormRequest;

class ControllerWithBareFormRequest
{
    public function update(BareFormRequest $request): void
    {
        // handled by form request
    }
}
