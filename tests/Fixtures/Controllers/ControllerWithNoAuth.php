<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

class ControllerWithNoAuth
{
    public function show($user): void
    {
        // no authorisation check
    }
}
