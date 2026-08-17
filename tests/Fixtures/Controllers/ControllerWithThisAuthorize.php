<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

class ControllerWithThisAuthorize
{
    public function update($order): void
    {
        $this->authorize('update', $order);
    }
}
