<?php

use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;
use Phoenix1331\LaravelAuthAudit\Scanning\AttributeResolver;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithClassAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithExpiredAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithMethodAttribute;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Controllers\ControllerWithNoAuth;
use Phoenix1331\LaravelAuthAudit\Tests\Support\RouteEntryFactory;

it('skips a route with a class-level WithoutAuthAudit attribute', function () {
    $resolver = new AttributeResolver;
    $entry = RouteEntryFactory::make(
        controller: ControllerWithClassAttribute::class,
        action: 'index',
    );

    $result = $resolver->resolve($entry);

    expect($result->status)->toBe(RouteStatus::Skipped)
        ->and($result->skipReason)->toBe('Public marketing pages');
});

it('skips a route with a method-level WithoutAuthAudit attribute', function () {
    $resolver = new AttributeResolver;
    $entry = RouteEntryFactory::make(
        controller: ControllerWithMethodAttribute::class,
        action: 'webhook',
    );

    $result = $resolver->resolve($entry);

    expect($result->status)->toBe(RouteStatus::Skipped)
        ->and($result->skipReason)->toBe('Signature verified via webhook secret');
});

it('does not skip a method without the attribute on a controller that has no class attribute', function () {
    $resolver = new AttributeResolver;
    $entry = RouteEntryFactory::make(
        controller: ControllerWithMethodAttribute::class,
        action: 'index',
    );

    $result = $resolver->resolve($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised);
});

it('reverts an expired bypass to unauthorised with anti-pattern label', function () {
    $resolver = new AttributeResolver;
    $entry = RouteEntryFactory::make(
        controller: ControllerWithExpiredAttribute::class,
        action: 'export',
    );

    $result = $resolver->resolve($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->antiPattern)->toStartWith('expired-bypass:');
});

it('does not modify an already-skipped entry', function () {
    $resolver = new AttributeResolver;
    $entry = RouteEntryFactory::make(
        controller: ControllerWithClassAttribute::class,
        action: 'index',
        status: RouteStatus::Skipped,
    );
    $entry->skipReason = 'excluded via middleware';

    $result = $resolver->resolve($entry);

    expect($result->skipReason)->toBe('excluded via middleware');
});

it('returns entry unchanged when controller has no attribute', function () {
    $resolver = new AttributeResolver;
    $entry = RouteEntryFactory::make(
        controller: ControllerWithNoAuth::class,
        action: 'show',
    );

    $result = $resolver->resolve($entry);

    expect($result->status)->toBe(RouteStatus::Unauthorised)
        ->and($result->skipReason)->toBeNull();
});
