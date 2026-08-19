<?php

namespace Phoenix1331\LaravelAuthAudit\Baseline;

use Phoenix1331\LaravelAuthAudit\Data\AuditReport;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;

class BaselineWriter
{
    public function write(AuditReport $report, string $path): void
    {
        $baseline = [];

        foreach ($report->routes as $entry) {
            if ($entry->status !== RouteStatus::Unauthorised) {
                continue;
            }

            $key = $this->routeSignature($entry);
            $baseline[$key] = [
                'uri' => $entry->uri,
                'method' => $entry->method,
                'controller' => $entry->controller,
                'action' => $entry->action,
                'anti_pattern' => $entry->antiPattern,
            ];
        }

        file_put_contents(
            $path,
            json_encode($baseline, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        );
    }

    public static function routeSignature(RouteEntry $entry): string
    {
        return implode('::', array_filter([
            $entry->method,
            $entry->uri,
            $entry->controller,
            $entry->action,
        ]));
    }

    public function load(string $path): ?array
    {
        if (! file_exists($path)) {
            return null;
        }

        $decoded = json_decode(file_get_contents($path), true);

        return is_array($decoded) ? $decoded : null;
    }
}
