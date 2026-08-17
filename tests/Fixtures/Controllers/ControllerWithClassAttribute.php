<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Attributes\WithoutAuthAudit;

#[WithoutAuthAudit('Public marketing pages')]
class ControllerWithClassAttribute
{
    public function index(): void {}
}
