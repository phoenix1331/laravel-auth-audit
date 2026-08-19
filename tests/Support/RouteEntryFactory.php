<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Support;

use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;

class RouteEntryFactory
{
    public static function make(
        string $uri = 'orders/{order}',
        string $method = 'GET',
        ?string $controller = null,
        ?string $action = null,
        array $middleware = [],
        array $boundModels = [],
        array $rawScalarParams = [],
        bool $unscopedNestedBinding = false,
        RouteStatus $status = RouteStatus::Unauthorised,
    ): RouteEntry {
        return new RouteEntry(
            uri: $uri,
            method: $method,
            name: null,
            controller: $controller,
            action: $action,
            boundModels: $boundModels,
            middleware: $middleware,
            rawScalarParams: $rawScalarParams,
            unscopedNestedBinding: $unscopedNestedBinding,
            status: $status,
        );
    }
}
