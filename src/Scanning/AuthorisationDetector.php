<?php

namespace Phoenix1331\LaravelAuthAudit\Scanning;

use Illuminate\Foundation\Http\FormRequest;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeFinder;
use PhpParser\Parser;
use PhpParser\ParserFactory;

class AuthorisationDetector
{
    private readonly Parser $parser;

    private readonly NodeFinder $nodeFinder;

    public function __construct(
        private readonly array $config,
        private readonly PolicyResolver $policyResolver,
    ) {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
        $this->nodeFinder = new NodeFinder;
    }

    public function detect(RouteEntry $entry): RouteEntry
    {
        if ($entry->status === RouteStatus::Skipped) {
            return $entry;
        }

        $entry = $this->runSignalChecks($entry);

        if ($entry->unscopedNestedBinding && $entry->status === RouteStatus::Authorised) {
            $entry->status = RouteStatus::Unauthorised;
            $entry->antiPattern = 'unscoped-nested-binding';
        }

        return $entry;
    }

    private function runSignalChecks(RouteEntry $entry): RouteEntry
    {
        if ($signal = $this->detectCanMiddleware($entry->middleware)) {
            $entry->status = RouteStatus::Authorised;
            $entry->detectedSignal = $signal;

            return $entry;
        }

        if ($signal = $this->detectCustomSignalInMiddleware($entry->middleware)) {
            $entry->status = RouteStatus::Authorised;
            $entry->detectedSignal = $signal;

            return $entry;
        }

        if ($entry->controller !== null && $entry->action !== null) {
            $controllerFile = $this->resolveControllerFile($entry->controller);

            if ($controllerFile !== null && file_exists($controllerFile)) {
                $ast = $this->parseFile($controllerFile);

                if ($ast !== null) {
                    if ($entry->boundModels !== [] && $this->detectClassLevelCheckOnInstanceRoute($ast, $entry->action)) {
                        $entry->status = RouteStatus::Unauthorised;
                        $entry->antiPattern = 'class-level-check-on-instance-route';

                        return $entry;
                    }

                    if ($signal = $this->detectInControllerMethod($ast, $entry->action)) {
                        $entry->status = RouteStatus::Authorised;
                        $entry->detectedSignal = $signal;

                        return $entry;
                    }

                    if ($formRequestClass = $this->detectFormRequestClass($ast, $entry->action)) {
                        if ($this->isFormRequestBareTrueAuthorize($formRequestClass)) {
                            $entry->status = RouteStatus::Unauthorised;
                            $entry->antiPattern = 'bare-true-form-request';

                            return $entry;
                        }

                        $entry->status = RouteStatus::Authorised;
                        $entry->detectedSignal = $formRequestClass.'::authorize()';

                        return $entry;
                    }
                }
            }
        }

        foreach ($entry->boundModels as $modelClass) {
            if ($signal = $this->detectPolicyMatch($modelClass, $entry->action)) {
                $entry->status = RouteStatus::Authorised;
                $entry->detectedSignal = $signal;

                return $entry;
            }
        }

        if ($signal = $this->detectCustomSignalInController($entry->controller)) {
            $entry->status = RouteStatus::Authorised;
            $entry->detectedSignal = $signal;

            return $entry;
        }

        if ($entry->unscopedNestedBinding) {
            $entry->status = RouteStatus::Unauthorised;
            $entry->antiPattern = 'unscoped-nested-binding';

            return $entry;
        }

        $entry->status = RouteStatus::Unauthorised;

        return $entry;
    }

    private function detectCanMiddleware(array $middleware): ?string
    {
        foreach ($middleware as $m) {
            if (str_starts_with($m, 'can:')) {
                return $m;
            }
        }

        return null;
    }

    private function detectCustomSignalInMiddleware(array $middleware): ?string
    {
        $signals = $this->config['custom_signals'] ?? [];

        foreach ($middleware as $m) {
            if (in_array($m, $signals, true)) {
                return 'custom: '.$m;
            }
        }

        return null;
    }

    private function detectCustomSignalInController(?string $controller): ?string
    {
        if ($controller === null) {
            return null;
        }

        $signals = $this->config['custom_signals'] ?? [];

        foreach ($signals as $signal) {
            if (str_contains($signal, '::') && str_starts_with($signal, $controller)) {
                return 'custom: '.$signal;
            }
        }

        return null;
    }

    /** @param Node[] $ast */
    private function detectClassLevelCheckOnInstanceRoute(array $ast, string $methodName): bool
    {
        $method = $this->findMethod($ast, $methodName);

        if ($method === null) {
            return false;
        }

        foreach ($this->nodeFinder->findInstanceOf($method, MethodCall::class) as $call) {
            if (! $call->name instanceof Identifier || $call->name->name !== 'authorize') {
                continue;
            }

            if ($this->secondArgIsClassConst($call->args)) {
                return true;
            }
        }

        foreach ($this->nodeFinder->findInstanceOf($method, StaticCall::class) as $call) {
            if (! $call->class instanceof Name || ! $call->name instanceof Identifier) {
                continue;
            }

            if ($call->class->toString() !== 'Gate') {
                continue;
            }

            if (! in_array($call->name->name, ['authorize', 'allows', 'check', 'any', 'none'], true)) {
                continue;
            }

            if ($this->secondArgIsClassConst($call->args)) {
                return true;
            }
        }

        return false;
    }

    /** @param Arg[] $args */
    private function secondArgIsClassConst(array $args): bool
    {
        if (count($args) < 2) {
            return false;
        }

        $second = $args[1]->value;

        return $second instanceof Node\Expr\ClassConstFetch
            && $second->name instanceof Identifier
            && $second->name->name === 'class';
    }

    /** @param Node[] $ast */
    private function detectInControllerMethod(array $ast, string $methodName): ?string
    {
        $method = $this->findMethod($ast, $methodName);

        if ($method === null) {
            return null;
        }

        if ($signal = $this->detectThisAuthorize($method)) {
            return $signal;
        }

        if ($signal = $this->detectGateCall($method)) {
            return $signal;
        }

        return null;
    }

    private function detectThisAuthorize(ClassMethod $method): ?string
    {
        $calls = $this->nodeFinder->findInstanceOf($method, MethodCall::class);

        foreach ($calls as $call) {
            if (! $call->name instanceof Identifier) {
                continue;
            }

            if ($call->name->name === 'authorize') {
                return '$this->authorize()';
            }
        }

        return null;
    }

    private function detectGateCall(ClassMethod $method): ?string
    {
        $calls = $this->nodeFinder->findInstanceOf($method, StaticCall::class);

        foreach ($calls as $call) {
            if (! $call->class instanceof Name) {
                continue;
            }

            if (! $call->name instanceof Identifier) {
                continue;
            }

            $class = $call->class->toString();
            $methodName = $call->name->name;

            if ($class === 'Gate' && in_array($methodName, ['authorize', 'allows', 'check', 'any', 'none'], true)) {
                return 'Gate::'.$methodName.'()';
            }
        }

        return null;
    }

    /** @param Node[] $ast */
    private function detectFormRequestClass(array $ast, string $methodName): ?string
    {
        $method = $this->findMethod($ast, $methodName);

        if ($method === null) {
            return null;
        }

        $useMap = $this->buildUseMap($ast);

        foreach ($method->params as $param) {
            $type = $param->type;

            if (! $type instanceof Name) {
                continue;
            }

            $className = $type->toString();
            $resolved = $this->resolveFormRequestClass($className, $useMap);

            if ($resolved !== null) {
                return $resolved;
            }
        }

        return null;
    }

    /**
     * @param  Node[]  $ast
     * @return array<string, string>
     */
    private function buildUseMap(array $ast): array
    {
        $map = [];
        $uses = $this->nodeFinder->findInstanceOf($ast, Node\Stmt\UseUse::class);

        foreach ($uses as $use) {
            $fqn = $use->name->toString();
            $alias = $use->alias ? $use->alias->toString() : class_basename($fqn);
            $map[$alias] = $fqn;
        }

        return $map;
    }

    /** @param array<string, string> $useMap */
    private function resolveFormRequestClass(string $className, array $useMap = []): ?string
    {
        $candidates = array_unique([
            $useMap[$className] ?? $className,
            $className,
            'App\\Http\\Requests\\'.$className,
        ]);

        foreach ($candidates as $candidate) {
            if (! class_exists($candidate)) {
                continue;
            }

            if (is_subclass_of($candidate, FormRequest::class)) {
                return $candidate;
            }
        }

        return null;
    }

    private function isFormRequestBareTrueAuthorize(string $formRequestClass): bool
    {
        if (! ($this->config['flag_bare_true_form_requests'] ?? true)) {
            return false;
        }

        $file = $this->resolveClassFile($formRequestClass);

        if ($file === null || ! file_exists($file)) {
            return false;
        }

        $ast = $this->parseFile($file);

        if ($ast === null) {
            return false;
        }

        $method = $this->findMethod($ast, 'authorize');

        if ($method === null) {
            return false;
        }

        $stmts = $method->stmts ?? [];

        if (count($stmts) !== 1) {
            return false;
        }

        $stmt = $stmts[0];

        if (! $stmt instanceof Return_) {
            return false;
        }

        return $stmt->expr instanceof Node\Expr\ConstFetch
            && strtolower($stmt->expr->name->toString()) === 'true';
    }

    private function detectPolicyMatch(string $modelClass, ?string $routeAction): ?string
    {
        if ($routeAction === null) {
            return null;
        }

        return $this->policyResolver->resolveForRoute($modelClass, $routeAction);
    }

    /** @param Node[] $ast */
    private function findMethod(array $ast, string $name): ?ClassMethod
    {
        $methods = $this->nodeFinder->findInstanceOf($ast, ClassMethod::class);

        foreach ($methods as $method) {
            if ($method->name->toString() === $name) {
                return $method;
            }
        }

        return null;
    }

    /** @return Node[]|null */
    private function parseFile(string $path): ?array
    {
        try {
            return $this->parser->parse(file_get_contents($path));
        } catch (\Throwable) {
            return null;
        }
    }

    private function resolveControllerFile(string $controllerClass): ?string
    {
        return $this->resolveClassFile($controllerClass);
    }

    private function resolveClassFile(string $className): ?string
    {
        if (! class_exists($className)) {
            $scanPaths = $this->config['scan_paths'] ?? [];

            foreach ($scanPaths as $path) {
                $short = class_basename($className);
                $candidate = rtrim($path, '/').'/'.$short.'.php';

                if (file_exists($candidate)) {
                    return $candidate;
                }
            }

            return null;
        }

        try {
            $ref = new \ReflectionClass($className);

            return $ref->getFileName() ?: null;
        } catch (\ReflectionException) {
            return null;
        }
    }
}
