<?php

namespace Phoenix1331\LaravelAuthAudit\Scanning;

use Illuminate\Contracts\Auth\Access\Gate;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;

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

    public function isPolicyMethodInstanceBlind(string $policyClass, string $methodName): bool
    {
        try {
            $ref = new \ReflectionClass($policyClass);
        } catch (\ReflectionException) {
            return false;
        }

        $file = $ref->getFileName();

        if ($file === false || ! file_exists($file)) {
            return false;
        }

        $parser = (new ParserFactory)->createForNewestSupportedVersion();

        try {
            $ast = $parser->parse(file_get_contents($file));
        } catch (\Throwable) {
            return false;
        }

        if ($ast === null) {
            return false;
        }

        $nodeFinder = new NodeFinder;
        $methods = $nodeFinder->findInstanceOf($ast, ClassMethod::class);

        foreach ($methods as $method) {
            if ($method->name->toString() !== $methodName) {
                continue;
            }

            // No model parameter at all — instance-blind
            $modelParam = $this->findModelParam($method);

            if ($modelParam === null) {
                return true;
            }

            // Has a model param but never references it in the body — instance-blind
            $paramName = $modelParam;
            $usages = $nodeFinder->findInstanceOf($method->stmts ?? [], Variable::class);

            foreach ($usages as $var) {
                if ($var->name === $paramName) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    private function findModelParam(ClassMethod $method): ?string
    {
        // Skip first param (the authenticated user by convention)
        $params = array_slice($method->params, 1);

        foreach ($params as $param) {
            $type = $param->type;

            if ($type === null) {
                continue;
            }

            $typeName = $type instanceof Name ? $type->toString() : null;

            if ($typeName === null) {
                continue;
            }

            // Any non-primitive type hint in the second+ position is the model param
            if (! in_array(strtolower($typeName), ['int', 'string', 'bool', 'float', 'array', 'mixed'], true)) {
                return is_string($param->var->name) ? $param->var->name : null;
            }
        }

        return null;
    }
}
