<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use App\Models\User;

class ControllerWithUnscopedFind
{
    public function show($id): void
    {
        $user = User::findOrFail($id);
    }
}
