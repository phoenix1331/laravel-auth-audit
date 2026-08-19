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

        if ($entry->antiPattern === null && $entry->rawScalarParams !== [] && $entry->controller !== null && $entry->action !== null) {
            $controllerFile = $this->resolveControllerFile($entry->controller);

            if ($controllerFile !== null && file_exists($controllerFile)) {
                $ast = $this->parseFile($controllerFile);

                if ($ast !== null && $this->detectUnscopedRetrieval($ast, $entry->action, $entry->rawScalarParams)) {
                    $entry->status = RouteStatus::Unauthorised;
                    $entry->antiPattern = 'unbound-identifier';
                }
            }
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
                    if ($signal = $this->detectAuthorizeResource($ast)) {
                        $entry->status = RouteStatus::Authorised;
                        $entry->detectedSignal = $signal;

                        return $entry;
                    }

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
                if ($this->isPolicyInstanceBlind($modelClass, $entry->action)) {
                    $entry->status = RouteStatus::Unauthorised;
                    $entry->antiPattern = 'instance-blind-policy';

                    return $entry;
                }

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

            if (! in_array($call->name->name, ['authorize', 'allows', 'check', 'any', 'none', 'inspect'], true)) {
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

        if ($signal = $this->detectRelationshipScopedRetrieval($method)) {
            return $signal;
        }

        if ($signal = $this->detectAbortUnlessCanCall($method)) {
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

            if ($class === 'Gate' && in_array($methodName, ['authorize', 'allows', 'check', 'any', 'none', 'inspect'], true)) {
                return 'Gate::'.$methodName.'()';
            }
        }

        return null;
    }

    private function detectRelationshipScopedRetrieval(ClassMethod $method): ?string
    {
        $retrievalMethods = ['find', 'findOrFail', 'firstWhere', 'where', 'first'];

        foreach ($this->nodeFinder->findInstanceOf($method, MethodCall::class) as $call) {
            if (! $call->name instanceof Identifier) {
                continue;
            }

            if (! in_array($call->name->name, $retrievalMethods, true)) {
                continue;
            }

            if ($this->isRelationshipScopedChain($call->var)) {
                return 'relationship-scoped retrieval';
            }
        }

        return null;
    }

    /** @param Node[] $ast */
    private function detectAuthorizeResource(array $ast): ?string
    {
        $constructor = $this->findMethod($ast, '__construct');

        if ($constructor === null) {
            return null;
        }

        foreach ($this->nodeFinder->findInstanceOf($constructor, MethodCall::class) as $call) {
            if ($call->name instanceof Identifier && $call->name->name === 'authorizeResource') {
                return '$this->authorizeResource()';
            }
        }

        return null;
    }

    private function detectAbortUnlessCanCall(ClassMethod $method): ?string
    {
        foreach ($this->nodeFinder->findInstanceOf($method, Node\Expr\FuncCall::class) as $call) {
            if (! $call->name instanceof Name) {
                continue;
            }

            $funcName = $call->name->toString();

            if (! in_array($funcName, ['abort_unless', 'abort_if'], true)) {
                continue;
            }

            if ($call->args === []) {
                continue;
            }

            $condition = $call->args[0]->value;

            if ($this->conditionContainsCanCall($condition)) {
                return $funcName.'($user->can(...))';
            }
        }

        return null;
    }

    private function conditionContainsCanCall(Node $node): bool
    {
        // $user->can(...) or auth()->user()->can(...)
        if ($node instanceof MethodCall && $node->name instanceof Identifier && $node->name->name === 'can') {
            return true;
        }

        // !$user->can(...) — BooleanNot wrapping a can() call
        if ($node instanceof Node\Expr\BooleanNot) {
            return $this->conditionContainsCanCall($node->expr);
        }

        return false;
    }

    private function isRelationshipScopedChain(Node $node): bool
    {
        // Matches: $request->user()->relationship() or auth()->user()->relationship()
        if (! $node instanceof MethodCall) {
            return false;
        }

        // The immediate receiver must be a method call (the relationship)
        $receiver = $node->var;

        if (! $receiver instanceof MethodCall) {
            return false;
        }

        // Check for ->user() call
        if ($receiver->name instanceof Identifier && $receiver->name->name === 'user') {
            $root = $receiver->var;

            // $request->user()
            if ($root instanceof Node\Expr\Variable && $root->name === 'request') {
                return true;
            }

            // auth()->user()
            if ($root instanceof Node\Expr\FuncCall
                && $root->name instanceof Name
                && $root->name->toString() === 'auth') {
                return true;
            }
        }

        return false;
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

    /**
     * @param  Node[]  $ast
     * @param  string[]  $rawScalarParams
     */
    private function detectUnscopedRetrieval(array $ast, string $methodName, array $rawScalarParams): bool
    {
        $method = $this->findMethod($ast, $methodName);

        if ($method === null) {
            return false;
        }

        $unscopedMethods = ['find', 'findOrFail', 'firstWhere', 'where'];

        foreach ($this->nodeFinder->findInstanceOf($method, StaticCall::class) as $call) {
            if (! $call->name instanceof Identifier) {
                continue;
            }

            if (! in_array($call->name->name, $unscopedMethods, true)) {
                continue;
            }

            if ($call->args === []) {
                continue;
            }

            $firstArg = $call->args[0]->value;

            if ($this->argTracesToRawParam($firstArg, $rawScalarParams)) {
                return true;
            }
        }

        return false;
    }

    /** @param string[] $rawScalarParams */
    private function argTracesToRawParam(Node $arg, array $rawScalarParams): bool
    {
        // Direct variable: find($id)
        if ($arg instanceof Node\Expr\Variable && is_string($arg->name)) {
            return in_array($arg->name, $rawScalarParams, true);
        }

        // Property access on request: find($request->id)
        if ($arg instanceof Node\Expr\PropertyFetch) {
            if ($arg->var instanceof Node\Expr\Variable && $arg->var->name === 'request') {
                return $arg->name instanceof Identifier
                    && in_array($arg->name->name, $rawScalarParams, true);
            }
        }

        // Method call on request: find($request->input('id')) or find($request->get('id'))
        if ($arg instanceof MethodCall) {
            if ($arg->var instanceof Node\Expr\Variable && $arg->var->name === 'request') {
                if (isset($arg->args[0])) {
                    $innerArg = $arg->args[0]->value;

                    return $innerArg instanceof Node\Scalar\String_
                        && in_array($innerArg->value, $rawScalarParams, true);
                }
            }
        }

        return false;
    }

    private function isPolicyInstanceBlind(string $modelClass, ?string $routeAction): bool
    {
        if ($routeAction === null) {
            return false;
        }

        $policyClass = $this->policyResolver->findPolicyClass($modelClass);

        if ($policyClass === null) {
            return false;
        }

        $policyMethod = $this->policyResolver->inferPolicyMethod($routeAction);

        return $this->policyResolver->isPolicyMethodInstanceBlind($policyClass, $policyMethod);
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
