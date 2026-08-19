<?php

use Illuminate\Contracts\Auth\Access\Gate;
use Phoenix1331\LaravelAuthAudit\Scanning\PolicyResolver;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\InstanceBlindPolicy;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\InstanceScopedPolicy;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\OrderPolicy;
use Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Policies\UnusedParamPolicy;

function makePolicyResolver(?string $policyClass = null): PolicyResolver
{
    $gate = Mockery::mock(Gate::class);
    $gate->shouldReceive('getPolicyFor')->andReturn($policyClass);

    return new PolicyResolver($gate);
}

it('returns null when no policy is registered for the model', function () {
    $resolver = makePolicyResolver(null);

    expect($resolver->findPolicyClass('App\\Models\\Order'))->toBeNull();
});

it('returns the policy class when one is registered', function () {
    $resolver = makePolicyResolver(OrderPolicy::class);

    expect($resolver->findPolicyClass('App\\Models\\Order'))->toBe(OrderPolicy::class);
});

it('infers view for show and index actions', function () {
    $resolver = makePolicyResolver();

    expect($resolver->inferPolicyMethod('show'))->toBe('view')
        ->and($resolver->inferPolicyMethod('index'))->toBe('view');
});

it('infers create for create and store actions', function () {
    $resolver = makePolicyResolver();

    expect($resolver->inferPolicyMethod('create'))->toBe('create')
        ->and($resolver->inferPolicyMethod('store'))->toBe('create');
});

it('infers update for edit and update actions', function () {
    $resolver = makePolicyResolver();

    expect($resolver->inferPolicyMethod('edit'))->toBe('update')
        ->and($resolver->inferPolicyMethod('update'))->toBe('update');
});

it('infers delete for destroy action', function () {
    $resolver = makePolicyResolver();

    expect($resolver->inferPolicyMethod('destroy'))->toBe('delete');
});

it('passes through unknown actions unchanged', function () {
    $resolver = makePolicyResolver();

    expect($resolver->inferPolicyMethod('approve'))->toBe('approve');
});

it('resolves a matching policy method for a route', function () {
    $resolver = makePolicyResolver(OrderPolicy::class);

    expect($resolver->resolveForRoute('App\\Models\\Order', 'update'))
        ->toBe(OrderPolicy::class.'@update');
});

it('returns null when policy does not have the required method', function () {
    $resolver = makePolicyResolver(OrderPolicy::class);

    expect($resolver->resolveForRoute('App\\Models\\Order', 'forceDelete'))->toBeNull();
});

it('returns null when no policy is registered', function () {
    $resolver = makePolicyResolver(null);

    expect($resolver->resolveForRoute('App\\Models\\Order', 'update'))->toBeNull();
});

it('detects instance-blind policy with no model param', function () {
    $resolver = makePolicyResolver(InstanceBlindPolicy::class);

    expect($resolver->isPolicyMethodInstanceBlind(InstanceBlindPolicy::class, 'update'))->toBeTrue();
});

it('detects instance-blind policy with unused model param', function () {
    $resolver = makePolicyResolver(UnusedParamPolicy::class);

    expect($resolver->isPolicyMethodInstanceBlind(UnusedParamPolicy::class, 'update'))->toBeTrue();
});

it('does not flag a policy that references the model param', function () {
    $resolver = makePolicyResolver(InstanceScopedPolicy::class);

    expect($resolver->isPolicyMethodInstanceBlind(InstanceScopedPolicy::class, 'update'))->toBeFalse();
});

it('returns false for isPolicyMethodInstanceBlind when method does not exist', function () {
    $resolver = makePolicyResolver(InstanceScopedPolicy::class);

    expect($resolver->isPolicyMethodInstanceBlind(InstanceScopedPolicy::class, 'nonExistent'))->toBeFalse();
});
