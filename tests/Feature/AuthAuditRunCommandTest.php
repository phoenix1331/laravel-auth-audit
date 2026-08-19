<?php

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithAbortUnlessCan;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithAuthorizeResource;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithClassAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithClassLevelCheck;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithDiscardedGateResult;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithExpiredAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithGateAuthorize;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithGateInspect;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithInstanceScopedFormRequest;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithNestedBinding;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithNoAuth;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithNoAuthAndModel;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithRelationshipScope;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithThisAuthorize;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithUnscopedFind;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Models\Order;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\InstanceBlindPolicy;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\InstanceScopedPolicy;

it('runs successfully and outputs a coverage summary', function () {
    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $this->artisan('auth-audit:run')
        ->expectsOutputToContain('Coverage:')
        ->assertSuccessful();
});

it('exits with failure when coverage is below min threshold', function () {
    Route::get('/users/{user}', [ControllerWithNoAuth::class, 'show']);

    $this->artisan('auth-audit:run', ['--min' => 100])
        ->assertFailed();
});

it('exits successfully when coverage meets the threshold', function () {
    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->assertSuccessful();
});

it('exits successfully when --json flag is passed', function () {
    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $this->artisan('auth-audit:run', ['--json' => true])
        ->assertSuccessful();
});

it('detects an authorised route via $this->authorize()', function () {
    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $this->artisan('auth-audit:run')
        ->expectsOutputToContain('authorised')
        ->assertSuccessful();
});

it('detects an unauthorised route and shows it in output', function () {
    Route::get('/users/{user}', [ControllerWithNoAuth::class, 'show']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('unauthorised');
});

it('skips a route with a class-level WithoutAuthAudit attribute', function () {
    Route::get('/marketing', [ControllerWithClassAttribute::class, 'index']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('skipped');
});

it('flags an expired bypass as unauthorised', function () {
    Route::get('/export', [ControllerWithExpiredAttribute::class, 'export']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('expired-bypass');
});

it('skips a route with the withoutAuthAudit route macro', function () {
    Route::get('/up', fn () => 'ok')->withoutAuthAudit('Health check, no auth required');

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('skipped');
});

it('writes an html report file when --html is passed', function () {
    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $path = sys_get_temp_dir().'/auth-audit-test-'.uniqid().'.html';

    $this->artisan('auth-audit:run', ['--html' => $path, '--min' => 0])
        ->assertSuccessful();

    expect(file_exists($path))->toBeTrue();
    expect(file_get_contents($path))->toContain('Auth Audit Report');

    unlink($path);
});

it('detects Gate::authorize() in controller method', function () {
    Route::get('/invoices/{invoice}', [ControllerWithGateAuthorize::class, 'destroy']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('exits cleanly when auth-audit is disabled via config', function () {
    config(['auth-audit.enabled' => false]);

    $this->artisan('auth-audit:run')
        ->assertSuccessful();
});

it('flags unscoped-nested-binding anti-pattern on a route with two bound models', function () {
    Route::get('/teams/{team}/orders/{order}', [ControllerWithNestedBinding::class, 'show']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('unscoped-nested-binding');
});

it('does not flag unscoped-nested-binding on a single-model route', function () {
    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('flags class-level-check-on-instance-route anti-pattern in output', function () {
    Route::put('/orders/{order}', [ControllerWithClassLevelCheck::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('class-level-check-on-instance-route');
});

it('flags instance-blind-policy when policy method has no model param', function () {
    Gate::policy(Order::class, InstanceBlindPolicy::class);
    Route::put('/orders/{order}', [ControllerWithNoAuthAndModel::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('instance-blind-policy');
});

it('does not flag instance-blind-policy when policy method references the model', function () {
    Gate::policy(Order::class, InstanceScopedPolicy::class);
    Route::put('/orders/{order}', [ControllerWithNoAuthAndModel::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('flags unbound-identifier on a route with a raw scalar param and unscoped findOrFail', function () {
    Route::get('/users/{id}', [ControllerWithUnscopedFind::class, 'show']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('unbound-identifier');
});

it('counts relationship-scoped retrieval as authorised and does not flag unbound-identifier', function () {
    Route::get('/orders/{id}', [ControllerWithRelationshipScope::class, 'show']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('counts authorizeResource() in constructor as authorised', function () {
    Route::put('/orders/{order}', [ControllerWithAuthorizeResource::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('counts abort_unless($user->can()) as authorised', function () {
    Route::put('/orders/{order}', [ControllerWithAbortUnlessCan::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('counts Gate::inspect() as authorised', function () {
    Route::put('/orders/{order}', [ControllerWithGateInspect::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('authorised');
});

it('marks instance-scoped form request with [instance-scoped] label in output', function () {
    Route::put('/orders/{order}', [ControllerWithInstanceScopedFormRequest::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('instance-scoped');
});

it('flags discarded-gate-result anti-pattern in output', function () {
    Route::put('/orders/{order}', [ControllerWithDiscardedGateResult::class, 'update']);

    $this->artisan('auth-audit:run', ['--min' => 0])
        ->expectsOutputToContain('discarded-gate-result');
});

it('writes a baseline file when --generate-baseline is passed', function () {
    $path = sys_get_temp_dir().'/auth-audit-baseline-'.uniqid().'.json';
    Route::get('/users/{id}', [ControllerWithNoAuth::class, 'show']);

    $this->artisan('auth-audit:run', ['--generate-baseline' => true, '--compare' => $path])
        ->assertSuccessful();

    expect(file_exists($path))->toBeTrue();
    $data = json_decode(file_get_contents($path), true);
    expect($data)->toBeArray();

    unlink($path);
});

it('baseline file is keyed by route signature', function () {
    $path = sys_get_temp_dir().'/auth-audit-baseline-'.uniqid().'.json';
    Route::get('/users/{id}', [ControllerWithNoAuth::class, 'show']);

    $this->artisan('auth-audit:run', ['--generate-baseline' => true, '--compare' => $path])
        ->assertSuccessful();

    $data = json_decode(file_get_contents($path), true);
    $keys = array_keys($data);
    expect($keys)->not->toBeEmpty();
    expect($keys[0])->toContain('GET');

    unlink($path);
});

it('exits successfully when --generate-baseline is passed regardless of coverage', function () {
    $path = sys_get_temp_dir().'/auth-audit-baseline-'.uniqid().'.json';
    Route::get('/users/{id}', [ControllerWithNoAuth::class, 'show']);

    $this->artisan('auth-audit:run', ['--generate-baseline' => true, '--compare' => $path, '--min' => 100])
        ->assertSuccessful();

    unlink($path);
});

it('marks baselined violations as baselined and exits successfully', function () {
    $path = sys_get_temp_dir().'/auth-audit-baseline-'.uniqid().'.json';
    Route::get('/users/{id}', [ControllerWithNoAuth::class, 'show']);

    // generate baseline with the violation
    $this->artisan('auth-audit:run', ['--generate-baseline' => true, '--compare' => $path]);

    // re-run with the same violation — should now be baselined, exit 0 even at --min 100
    $this->artisan('auth-audit:run', ['--compare' => $path, '--min' => 100])
        ->assertSuccessful()
        ->expectsOutputToContain('baselined');

    unlink($path);
});

it('fails CI when a new violation is added that is not in the baseline', function () {
    $path = sys_get_temp_dir().'/auth-audit-baseline-'.uniqid().'.json';

    // baseline with one route
    Route::get('/users/{id}', [ControllerWithNoAuth::class, 'show']);
    $this->artisan('auth-audit:run', ['--generate-baseline' => true, '--compare' => $path]);

    // add a second unprotected route not in the baseline
    Route::get('/posts/{id}', [ControllerWithNoAuth::class, 'show']);
    $this->artisan('auth-audit:run', ['--compare' => $path, '--min' => 100])
        ->assertFailed();

    unlink($path);
});

it('reports stale baseline entries when baseline contains a route no longer present', function () {
    $path = sys_get_temp_dir().'/auth-audit-baseline-'.uniqid().'.json';

    // write a baseline containing a signature that will never match a registered route
    file_put_contents($path, json_encode([
        'GET::nonexistent/route::App\\Http\\Controllers\\GoneController::show' => [
            'uri' => 'nonexistent/route',
            'method' => 'GET',
            'controller' => 'App\\Http\\Controllers\\GoneController',
            'action' => 'show',
            'anti_pattern' => null,
        ],
    ]));

    Route::get('/orders/{order}', [ControllerWithThisAuthorize::class, 'update']);

    $this->artisan('auth-audit:run', ['--compare' => $path, '--min' => 0])
        ->expectsOutputToContain('stale baseline entries');

    unlink($path);
});
