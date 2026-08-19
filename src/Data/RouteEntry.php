<?php

namespace Phoenix1331\LaravelAuthAudit\Data;

class RouteEntry
{
    public function __construct(
        public readonly string $uri,
        public readonly string $method,
        public readonly ?string $name,
        public readonly ?string $controller,
        public readonly ?string $action,
        public readonly array $boundModels,
        public readonly array $middleware,
        public readonly array $rawScalarParams = [],
        public readonly bool $unscopedNestedBinding = false,
        public RouteStatus $status = RouteStatus::Unauthorised,
        public ?string $detectedSignal = null,
        public ?string $skipReason = null,
        public ?string $antiPattern = null,
    ) {}
}
