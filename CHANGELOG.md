# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-08-19

### Added

- Five new anti-pattern detections in `AuthorisationDetector`:
  - `unscoped-nested-binding` - routes with two or more bound model params where neither `->scopeBindings()` nor the parent-child naming convention applies
  - `class-level-check-on-instance-route` - `authorize()` or `Gate::*` called with `Model::class` instead of the bound instance
  - `instance-blind-policy` - policy method that has no model parameter or never references it in the method body (requires AST parsing of the policy file)
  - `unbound-identifier` - raw scalar param (`{id}`) with an unscoped `find`, `findOrFail`, `firstWhere`, or `where('id', ...)` in the controller body
  - `discarded-gate-result` - `Gate::allows()`, `Gate::check()`, or `Gate::any()` called as a bare statement whose return value is never used
- New positive signals recognised as authorised:
  - Relationship-scoped retrieval: `$request->user()->orders()->findOrFail($id)` and `auth()->user()->posts()->findOrFail($id)`
  - `$this->authorizeResource()` in the controller constructor
  - Route `->can('ability', 'model')` middleware (via existing middleware tier)
  - `abort_unless($user->can(...))` and `abort_if(!$user->can(...))`
  - `Gate::inspect()` with the result acted on
- Instance-scoped Form Request label: Form Requests whose `authorize()` method references `$this->route()` are now labelled `[instance-scoped]` in output rather than a generic signal
- `PolicyResolver::isPolicyMethodInstanceBlind()` - AST parsing of policy method bodies to detect policies that never reference the model parameter
- `--generate-baseline` flag on `auth-audit:run` - writes all current violations to a JSON file keyed by route signature (`METHOD::uri::controller::action`)
- `--compare` flag updated to consume the new baseline format; violations matching a baseline entry are marked `baselined` and excluded from the coverage percentage
- `RouteStatus::Baselined` enum case
- Stale baseline entry reporting - baseline entries that no longer match any registered route are counted and reported in console, JSON, and HTML output
- `baseline_path` key in `config/auth-audit.php` (default: `base_path('auth-audit-baseline.json')`)
- `baselined_count` and `stale_baseline_count` in JSON formatter output
- Baselined count in the console summary line
- Stale baseline warning in console output and HTML report
- `SECURITY.md` - vulnerability reporting policy
- `UPGRADING.md` - per-anti-pattern migration guide with before/after code examples and incremental adoption instructions

### Changed

- `AuthorisationDetector::detect()` restructured into `runSignalChecks()` with post-checks for anti-patterns that must override an existing positive signal (`unscoped-nested-binding`, `unbound-identifier`)
- Tier 3 policy detection now parses the policy method body in addition to checking method existence
- `--compare` flag previously expected a raw JSON report; it now expects the new baseline format (see UPGRADING.md)
- Console summary line now shows baselined count when non-zero
- HTML report Baselined filter button and `baselined` badge added
- Roadmap updated to reflect v2 shipping; runtime detection tier moved to v3

### Fixed

- `Gate::inspect()` was not previously recognised as an authorisation signal

## [1.0.0] - Unreleased

### Added

- `php artisan auth-audit:run` command with `--min`, `--json`, `--html`, and `--compare` flags
- Static route scanning via `RouteScanner` - walks Laravel's route collection and builds a `RouteEntry` per route
- Four-tier authorisation detection in `AuthorisationDetector`:
  - Tier 1: `can:` middleware detection
  - Tier 2: AST parsing of controller methods for `$this->authorize()`, `Gate::authorize()`, `Gate::allows()`, `Gate::check()`, `Gate::any()`, `Gate::none()`
  - Tier 3: Policy matching via `PolicyResolver` for Eloquent model bindings
  - Tier 4: `custom_signals` config escape hatch for non-standard patterns
- `bare-true-form-request` named anti-pattern detection for Form Requests with `authorize() { return true; }`
- `#[WithoutAuthAudit]` PHP 8.2 attribute for class-level and method-level bypasses with mandatory reason and optional expiry date
- `->withoutAuthAudit(string $reason)` route macro for closure-based route bypasses
- Expiry enforcement - past the expiry date, a bypass automatically reverts to a flagged violation
- Skip-count tracking as a separate metric from coverage percentage, surfaced in CI output as a delta vs baseline
- `ConsoleFormatter` - coloured table output with route, verb, detected signal, and status
- `JsonFormatter` - machine-readable JSON output for `--json` flag and `--compare` baseline files
- `HtmlFormatter` - self-contained single-file HTML report with inline CSS and JS, red/amber/green coverage banding, sortable/filterable route table, and dedicated exclusions section
- `config/auth-audit.php` with `enabled`, `min_coverage`, `exclude`, `exclude_middleware`, `scan_paths`, `custom_signals`, `flag_bare_true_form_requests`, `html.output_path`, `html.title`, and `require_exclusion_reasons` keys
- Config publishable via `php artisan vendor:publish --tag=auth-audit-config`
- Exit code `1` when coverage is below configured threshold, `0` otherwise
- Delta indicators in console and HTML output when `--compare` baseline is provided
- Support for Laravel 10, 11, 12, and 13
- Support for PHP 8.2, 8.3, and 8.4
- Pest test suite with Orchestra Testbench - 43 tests, 64 assertions
