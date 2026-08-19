<?php

use Illuminate\Contracts\Auth\Access\Gate;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;
use Phoenix1331\LaravelAuthAudit\Scanning\AuthorisationDetector;
use Phoenix1331\LaravelAuthAudit\Scanning\PolicyResolver;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithBareFormRequest;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithClassLevelCheck;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithGateAllows;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithGateAuthorize;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithGateClassLevelCheck;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithNoAuth;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithProperFormRequest;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithRelationshipScope;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithThisAuthorize;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithUnscopedFind;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithUnscopedRequestFind;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\InstanceBlindPolicy;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\InstanceScopedPolicy;
use Phoenix1331\LaravelAuthAudit\Tests\Support\RouteEntryFactory;

function makeDetector(array $config = [], ?string $policyClass = null): AuthorisationDetector
{
    $gate = Mockery::mock(Gate::class);
    $gate->shouldReceive('getPolicyFor')->andReturn($policyClass);

    $policyResolver = new PolicyResolver($gate);

    return new AuthorisationDetector(
        array_merge(['flag_bare_true_form_requests' => true], $config),
        $policyResolver,
    );
}

it('detects can middleware as authorised', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(middleware: ['auth', 'can:view-reports']);

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('can:view-reports');
});

it('detects this->authorize() in controller method', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithThisAuthorize::class,
        action: 'update',
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('$this->authorize()');
});

it('detects Gate::authorize() in controller method', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithGateAuthorize::class,
        action: 'destroy',
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('Gate::authorize()');
});

it('detects Gate::allows() in controller method', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithGateAllows::class,
        action: 'export',
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('Gate::allows()');
});

it('flags bare-true form request as unauthorised with anti-pattern', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithBareFormRequest::class,
        action: 'update',
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('bare-true-form-request');
});

it('treats proper form request authorize as authorised', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithProperFormRequest::class,
        action: 'update',
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised);
});

it('marks controller with no auth check as unauthorised', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithNoAuth::class,
        action: 'show',
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->detectedSignal)->toBeNull();
});

it('detects custom signal in middleware', function () {
    $detector = makeDetector(['custom_signals' => ['ensure.team.owner']]);
    $entry = RouteEntryFactory::make(middleware: ['auth', 'ensure.team.owner']);

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('custom: ensure.team.owner');
});

it('skips detection on already-skipped entries', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(status: RouteStatus::Skipped);
    $entry->skipReason = 'excluded via config';

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Skipped);
});

it('does not flag bare-true form request when config is disabled', function () {
    $detector = makeDetector(['flag_bare_true_form_requests' => false]);
    $entry = RouteEntryFactory::make(
        controller: ControllerWithBareFormRequest::class,
        action: 'update',
    );

    $result = $detector->detect($entry);

    expect($result->antiPattern)->toBeNull();
});

it('flags unbound-identifier when controller uses findOrFail with a raw scalar param', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'users/{id}',
        controller: ControllerWithUnscopedFind::class,
        action: 'show',
        rawScalarParams: ['id'],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('unbound-identifier');
});

it('flags unbound-identifier when controller uses find with $request->id', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'users/{id}',
        controller: ControllerWithUnscopedRequestFind::class,
        action: 'show',
        rawScalarParams: ['id'],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('unbound-identifier');
});

it('counts relationship-scoped retrieval via $request->user() as authorised', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'orders/{id}',
        controller: ControllerWithRelationshipScope::class,
        action: 'show',
        rawScalarParams: ['id'],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('relationship-scoped retrieval')
        ->and($result->antiPattern)->toBeNull();
});

it('counts relationship-scoped retrieval via auth()->user() as authorised', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'posts/{id}',
        controller: ControllerWithRelationshipScope::class,
        action: 'showViaAuth',
        rawScalarParams: ['id'],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->detectedSignal)->toBe('relationship-scoped retrieval')
        ->and($result->antiPattern)->toBeNull();
});

it('does not flag unbound-identifier when route has no raw scalar params', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'users/{id}',
        controller: ControllerWithUnscopedFind::class,
        action: 'show',
        rawScalarParams: [],
    );

    $result = $detector->detect($entry);

    expect($result->antiPattern)->not->toBe('unbound-identifier');
});

it('flags unscoped-nested-binding even when a check exists', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'teams/{team}/orders/{order}',
        controller: ControllerWithThisAuthorize::class,
        action: 'update',
        unscopedNestedBinding: true,
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('unscoped-nested-binding');
});

it('does not flag unscoped-nested-binding when entry is skipped', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'teams/{team}/orders/{order}',
        unscopedNestedBinding: true,
        status: RouteStatus::Skipped,
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Skipped)
        ->and($result->antiPattern)->toBeNull();
});

it('flags instance-blind-policy when policy method has no model param', function () {
    $detector = makeDetector(policyClass: InstanceBlindPolicy::class);
    $entry = RouteEntryFactory::make(
        uri: 'orders/{order}',
        action: 'update',
        boundModels: [Order::class],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('instance-blind-policy');
});

it('does not flag instance-blind-policy when policy method references the model', function () {
    $detector = makeDetector(policyClass: InstanceScopedPolicy::class);
    $entry = RouteEntryFactory::make(
        uri: 'orders/{order}',
        action: 'update',
        boundModels: [Order::class],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->antiPattern)->toBeNull();
});

it('flags class-level-check-on-instance-route for $this->authorize() with ::class', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithClassLevelCheck::class,
        action: 'update',
        boundModels: [Order::class],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('class-level-check-on-instance-route');
});

it('flags class-level-check-on-instance-route for Gate::authorize() with ::class', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithGateClassLevelCheck::class,
        action: 'update',
        boundModels: [Order::class],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toBe('class-level-check-on-instance-route');
});

it('does not flag class-level-check when route has no bound models', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithClassLevelCheck::class,
        action: 'update',
        boundModels: [],
    );

    $result = $detector->detect($entry);

    expect($result->antiPattern)->not->toBe('class-level-check-on-instance-route');
});

it('does not flag class-level-check when authorize() uses a variable', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        controller: ControllerWithThisAuthorize::class,
        action: 'update',
        boundModels: [Order::class],
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->antiPattern)->toBeNull();
});

it('does not flag unscoped-nested-binding when only one bound model', function () {
    $detector = makeDetector();
    $entry = RouteEntryFactory::make(
        uri: 'orders/{order}',
        controller: ControllerWithThisAuthorize::class,
        action: 'update',
        unscopedNestedBinding: false,
    );

    $result = $detector->detect($entry);

    expect($result->status)->toBe(RouteStatus::Authorised)
        ->and($result->antiPattern)->toBeNull();
});
