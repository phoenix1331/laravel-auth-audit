<?php

namespace Phoenix1331\LaravelAuthAudit\Scanning;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;

class RouteScanner
{
    public function __construct(
        private readonly Router $router,
        private readonly array $config,
    ) {}

    /** @return RouteEntry[] */
    public function scan(): array
    {
        $entries = [];

        foreach ($this->router->getRoutes() as $route) {
            $entries[] = $this->buildEntry($route);
        }

        return $entries;
    }

    private function buildEntry(Route $route): RouteEntry
    {
        $middleware = $this->resolveMiddleware($route);
        $controller = $this->resolveController($route);
        $action = $this->resolveAction($route);
        $boundModels = $this->resolveBoundModels($route);
        $uri = $route->uri();
        $method = implode('|', $route->methods());

        $entry = new RouteEntry(
            uri: $uri,
            method: $method,
            name: $route->getName(),
            controller: $controller,
            action: $action,
            boundModels: $boundModels,
            middleware: $middleware,
        );

        if ($this->isExcludedByMiddleware($middleware)) {
            $entry->status = RouteStatus::Skipped;
            $entry->skipReason = 'excluded via middleware';

            return $entry;
        }

        if ($excludeReason = $this->isExcludedByPattern($uri, $route->getName())) {
            $entry->status = RouteStatus::Skipped;
            $entry->skipReason = $excludeReason;

            return $entry;
        }

        if ($macroReason = $this->resolveRouteMacroBypass($route)) {
            $entry->status = RouteStatus::Skipped;
            $entry->skipReason = $macroReason;

            return $entry;
        }

        return $entry;
    }

    private function resolveController(Route $route): ?string
    {
        $action = $route->getAction();

        if (isset($action['controller'])) {
            $parts = explode('@', $action['controller']);

            return $parts[0] ?? null;
        }

        return null;
    }

    private function resolveAction(Route $route): ?string
    {
        $action = $route->getAction();

        if (isset($action['controller'])) {
            $parts = explode('@', $action['controller']);

            return $parts[1] ?? null;
        }

        return null;
    }

    private function resolveMiddleware(Route $route): array
    {
        return array_values(array_map(
            fn ($m) => is_string($m) ? $m : (string) $m,
            $route->gatherMiddleware(),
        ));
    }

    private function resolveBoundModels(Route $route): array
    {
        $models = [];

        foreach ($route->signatureParameters() as $parameter) {
            $type = $parameter->getType();

            if (! $type instanceof \ReflectionNamedType || $type->isBuiltin()) {
                continue;
            }

            $className = $type->getName();

            if (is_subclass_of($className, Model::class)) {
                $models[] = $className;
            }
        }

        return $models;
    }

    private function isExcludedByMiddleware(array $middleware): bool
    {
        $excludedMiddleware = $this->config['exclude_middleware'] ?? [];

        foreach ($middleware as $m) {
            if (in_array($m, $excludedMiddleware, true)) {
                return true;
            }
        }

        return false;
    }

    private function isExcludedByPattern(string $uri, ?string $name): ?string
    {
        $excludes = $this->config['exclude'] ?? [];

        foreach ($excludes as $entry) {
            $pattern = is_array($entry) ? ($entry['pattern'] ?? '') : $entry;
            $reason = is_array($entry) ? ($entry['reason'] ?? 'excluded via config') : 'excluded via config';

            if (fnmatch($pattern, $uri) || fnmatch($pattern, $name ?? '')) {
                return $reason;
            }
        }

        return null;
    }

    private function resolveRouteMacroBypass(Route $route): ?string
    {
        $action = $route->getAction();

        return $action['without_auth_audit'] ?? null;
    }
}
