<?php

namespace Phoenix1331\LaravelAuthAudit;

use Illuminate\Routing\Route;
use Illuminate\Support\ServiceProvider;
use Phoenix1331\LaravelAuthAudit\Console\AuthAuditRunCommand;

class LaravelAuthAuditServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/auth-audit.php',
            'auth-audit'
        );
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/auth-audit.php' => config_path('auth-audit.php'),
            ], 'auth-audit-config');

            $this->commands([
                AuthAuditRunCommand::class,
            ]);
        }

        $this->registerRouteMacro();
    }

    private function registerRouteMacro(): void
    {
        Route::macro('withoutAuthAudit', function (string $reason): Route {
            /** @var Route $this */
            $this->action['without_auth_audit'] = $reason;

            return $this;
        });
    }
}
