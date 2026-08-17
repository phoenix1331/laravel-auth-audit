<?php

use Illuminate\Support\Facades\Route;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithClassAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithExpiredAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithGateAuthorize;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithNoAuth;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithThisAuthorize;

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
