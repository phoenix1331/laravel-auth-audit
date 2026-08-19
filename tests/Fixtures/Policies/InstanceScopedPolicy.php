<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies;

use Illuminate\Foundation\Auth\User;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class InstanceScopedPolicy
{
    // model param referenced — genuinely instance-scoped
    public function update(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }
}
