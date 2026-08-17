# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
