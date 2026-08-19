<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies;

use Illuminate\Foundation\Auth\User;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;

class UnusedParamPolicy
{
    // model param declared but never referenced — instance-blind
    public function update(User $user, Order $order): bool
    {
        return $user->isAdmin();
    }
}
