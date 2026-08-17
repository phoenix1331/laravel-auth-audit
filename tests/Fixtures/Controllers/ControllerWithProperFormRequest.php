<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests\ProperFormRequest;

class ControllerWithProperFormRequest
{
    public function update(ProperFormRequest $request): void
    {
        // handled by form request
    }
}
