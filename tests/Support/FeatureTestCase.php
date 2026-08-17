<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Support;

use Orchestra\Testbench\TestCase;
use Phoenix1331\LaravelAuthAudit\LaravelAuthAuditServiceProvider;

class FeatureTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [LaravelAuthAuditServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth-audit.enabled', true);
        $app['config']->set('auth-audit.min_coverage', 80);
        $app['config']->set('auth-audit.exclude', []);
        $app['config']->set('auth-audit.exclude_middleware', ['guest']);
        $app['config']->set('auth-audit.custom_signals', []);
        $app['config']->set('auth-audit.flag_bare_true_form_requests', true);
        $app['config']->set('auth-audit.scan_paths', []);
    }
}
