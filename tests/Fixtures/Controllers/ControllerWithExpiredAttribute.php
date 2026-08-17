<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Attributes\WithoutAuthAudit;

class ControllerWithExpiredAttribute
{
    #[WithoutAuthAudit('Temporary bypass', expires: '2020-01-01')]
    public function export(): void {}
}
