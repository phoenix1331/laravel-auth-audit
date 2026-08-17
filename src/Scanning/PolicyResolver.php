<?php

namespace Phoenix1331\LaravelAuthAudit\Scanning;

use Illuminate\Contracts\Auth\Access\Gate;

class PolicyResolver
{
    public function __construct(
        private readonly Gate $gate,
    ) {}

    public function findPolicyClass(string $modelClass): ?string
    {
        $policy = $this->gate->getPolicyFor($modelClass);

        if ($policy === null) {
            return null;
        }

        return is_object($policy) ? $policy::class : $policy;
    }

    public function policyHasMethod(string $policyClass, string $method): bool
    {
        return method_exists($policyClass, $method);
    }

    public function inferPolicyMethod(string $routeAction): ?string
    {
        return match (strtolower($routeAction)) {
            'index', 'show' => 'view',
            'create', 'store' => 'create',
            'edit', 'update' => 'update',
            'destroy' => 'delete',
            default => $routeAction,
        };
    }

    public function resolveForRoute(string $modelClass, ?string $routeAction): ?string
    {
        $policyClass = $this->findPolicyClass($modelClass);

        if ($policyClass === null) {
            return null;
        }

        if ($routeAction === null) {
            return null;
        }

        $policyMethod = $this->inferPolicyMethod($routeAction);

        if (! $this->policyHasMethod($policyClass, $policyMethod)) {
            return null;
        }

        return $policyClass.'@'.$policyMethod;
    }
}
