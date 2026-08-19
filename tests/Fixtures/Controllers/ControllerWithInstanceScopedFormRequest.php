<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests\InstanceScopedFormRequest;

class ControllerWithInstanceScopedFormRequest
{
    public function update(InstanceScopedFormRequest $request): void {}
}
