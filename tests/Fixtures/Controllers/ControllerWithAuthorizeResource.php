<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers;

use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class ControllerWithAuthorizeResource
{
    public function __construct()
    {
        $this->authorizeResource(Order::class, 'order');
    }

    public function index(): void {}

    public function show(Order $order): void {}

    public function update(Order $order): void {}
}
