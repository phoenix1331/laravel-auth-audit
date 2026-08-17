<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Attributes\WithoutAuthAudit;

class ControllerWithMethodAttribute
{
    #[WithoutAuthAudit('Signature verified via webhook secret')]
    public function webhook(): void {}

    public function index(): void {}
}
