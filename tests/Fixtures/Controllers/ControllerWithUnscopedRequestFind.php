<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class ControllerWithUnscopedRequestFind
{
    public function show(Request $request): void
    {
        $user = User::find($request->id);
    }
}
