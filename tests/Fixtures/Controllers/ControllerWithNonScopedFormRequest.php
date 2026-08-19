<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests\NonScopedFormRequest;

class ControllerWithNonScopedFormRequest
{
    public function update(NonScopedFormRequest $request): void {}
}
