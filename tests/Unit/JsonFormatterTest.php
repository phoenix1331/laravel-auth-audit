<?php

use Phoenix1331\LaravelAuthAudit\Data\AuditReport;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;
use Phoenix1331\LaravelAuthAudit\Formatters\JsonFormatter;
use Phoenix1331\LaravelAuthAudit\Tests\Support\RouteEntryFactory;

function makeReport(array $routes = []): AuditReport
{
    $authorised = count(array_filter($routes, fn ($r) => $r->status === RouteStatus::Authorised));
    $unauthorised = count(array_filter($routes, fn ($r) => $r->status === RouteStatus::Unauthorised));
    $skipped = count(array_filter($routes, fn ($r) => $r->status === RouteStatus::Skipped));
    $scoreable = $authorised + $unauthorised;
    $coverage = $scoreable > 0 ? round(($authorised / $scoreable) * 100, 2) : 100.0;

    return new AuditReport(
        routes: $routes,
        totalRoutes: count($routes),
        authorisedCount: $authorised,
        unauthorisedCount: $unauthorised,
        skippedCount: $skipped,
        excludedCount: 0,
        coveragePercentage: $coverage,
    );
}

it('renders valid json', function () {
    $report = makeReport();
    $json = (new JsonFormatter)->render($report);

    expect(json_decode($json, true))->toBeArray();
});

it('includes coverage percentage in output', function () {
    $entry = RouteEntryFactory::make(status: RouteStatus::Authorised);
    $report = makeReport([$entry]);

    $data = json_decode((new JsonFormatter)->render($report), true);

    expect($data['coverage_percentage'])->toEqual(100.0);
});

it('includes per-route status in output', function () {
    $entry = RouteEntryFactory::make(uri: 'orders/{order}', status: RouteStatus::Unauthorised);
    $report = makeReport([$entry]);

    $data = json_decode((new JsonFormatter)->render($report), true);

    expect($data['routes'][0]['status'])->toBe('unauthorised')
        ->and($data['routes'][0]['uri'])->toBe('orders/{order}');
});

it('includes counts in output', function () {
    $authorised = RouteEntryFactory::make(status: RouteStatus::Authorised);
    $unauthorised = RouteEntryFactory::make(status: RouteStatus::Unauthorised);
    $report = makeReport([$authorised, $unauthorised]);

    $data = json_decode((new JsonFormatter)->render($report), true);

    expect($data['authorised_count'])->toBe(1)
        ->and($data['unauthorised_count'])->toBe(1)
        ->and($data['total_routes'])->toBe(2);
});

it('toArray returns the same structure as render', function () {
    $report = makeReport();
    $formatter = new JsonFormatter;

    expect($formatter->toArray($report))->toEqual(json_decode($formatter->render($report), true));
});
