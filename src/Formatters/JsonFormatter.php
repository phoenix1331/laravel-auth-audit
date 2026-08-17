<?php

namespace Phoenix1331\LaravelAuthAudit\Formatters;

use Phoenix1331\LaravelAuthAudit\Data\AuditReport;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;

class JsonFormatter
{
    public function render(AuditReport $report): string
    {
        return json_encode($this->toArray($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function toArray(AuditReport $report): array
    {
        return [
            'coverage_percentage' => $report->coveragePercentage,
            'total_routes' => $report->totalRoutes,
            'authorised_count' => $report->authorisedCount,
            'unauthorised_count' => $report->unauthorisedCount,
            'skipped_count' => $report->skippedCount,
            'excluded_count' => $report->excludedCount,
            'routes' => array_map($this->serializeRoute(...), $report->routes),
        ];
    }

    private function serializeRoute(RouteEntry $entry): array
    {
        return [
            'uri' => $entry->uri,
            'method' => $entry->method,
            'name' => $entry->name,
            'controller' => $entry->controller,
            'action' => $entry->action,
            'bound_models' => $entry->boundModels,
            'middleware' => $entry->middleware,
            'status' => $entry->status->value,
            'detected_signal' => $entry->detectedSignal,
            'skip_reason' => $entry->skipReason,
            'anti_pattern' => $entry->antiPattern,
        ];
    }
}
