<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Illuminate\Http\Request;

class ControllerWithRelationshipScope
{
    public function show(Request $request, $id): void
    {
        $order = $request->user()->orders()->findOrFail($id);
    }

    public function showViaAuth($id): void
    {
        $post = auth()->user()->posts()->findOrFail($id);
    }
}
