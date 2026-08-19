<?php

return [

    /*
     * Enable or disable the audit globally. Set to false in local environments
     * to skip the scan without removing the dev dependency.
     */
    'enabled' => env('AUTH_AUDIT_ENABLED', true),

    /*
     * CI coverage gate. The command exits with code 1 when coverage drops
     * below this percentage. Set to 0 to disable the gate.
     */
    'min_coverage' => env('AUTH_AUDIT_MIN_COVERAGE', 80),

    /*
     * Route name or URI patterns excluded from the audit. These are routes
     * that are intentionally public and require no authorisation check.
     *
     * When require_exclusion_reasons is true, each entry must be an array
     * with 'pattern' and 'reason' keys instead of a plain string.
     */
    'exclude' => [
        ['pattern' => 'login', 'reason' => 'Public authentication endpoint'],
        ['pattern' => 'register', 'reason' => 'Public registration endpoint'],
        ['pattern' => 'password/*', 'reason' => 'Public password reset flow'],
        ['pattern' => 'up', 'reason' => 'Health check endpoint, no sensitive data'],
        ['pattern' => 'sanctum/*', 'reason' => 'Sanctum CSRF cookie endpoint'],
    ],

    /*
     * Routes behind any of these middleware are excluded automatically.
     * The 'guest' middleware guards endpoints that are already inaccessible
     * to authenticated users, so authorisation is not applicable.
     */
    'exclude_middleware' => [
        'guest',
    ],

    /*
     * Directories scanned to resolve controller class files.
     * Extend this list to cover Livewire components or other action classes.
     */
    'scan_paths' => [
        app_path('Http/Controllers'),
    ],

    /*
     * Additional class names, method names, or middleware strings that should
     * count as a confirmed authorisation signal. Use this for service-layer
     * authorisation, custom middleware, or other non-standard patterns the
     * static detector cannot infer automatically.
     *
     * Example:
     *   'custom_signals' => [
     *       'App\\Services\\TeamAuthService::authorize',
     *       'ensure.team.owner',
     *   ],
     */
    'custom_signals' => [],

    /*
     * When true, a Form Request whose authorize() method contains only
     * "return true;" is flagged as a named anti-pattern rather than counted
     * as an authorisation signal.
     */
    'flag_bare_true_form_requests' => true,

    /*
     * HTML report settings. Used when --html is passed to auth-audit:run.
     */
    'html' => [
        'output_path' => storage_path('auth-audit/report.html'),
        'title' => 'Auth Audit Report',
    ],

    /*
     * When true, every entry in the 'exclude' array must supply a 'reason'
     * string. This prevents the coverage number from being inflated by
     * silently excluding routes without documentation.
     */
    'require_exclusion_reasons' => true,

    /*
     * Path where --generate-baseline writes the baseline file, and where
     * subsequent runs load it from when no --compare path is given.
     * Commit this file to version control so CI can compare against it.
     */
    'baseline_path' => base_path('auth-audit-baseline.json'),

];
