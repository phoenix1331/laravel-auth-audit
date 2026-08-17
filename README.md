# laravel-auth-audit

[![Packagist Version](https://img.shields.io/packagist/v/phoenix1331/laravel-auth-audit)](https://packagist.org/packages/phoenix1331/laravel-auth-audit)
[![PHP](https://img.shields.io/badge/php-8.2%2B-blue)](https://www.php.net)
[![Laravel](https://img.shields.io/badge/laravel-10%20%7C%2011%20%7C%2012%20%7C%2013-red)](https://laravel.com)
[![Build](https://img.shields.io/github/actions/workflow/status/phoenix1331/laravel-auth-audit/tests.yml?branch=main)](https://github.com/phoenix1331/laravel-auth-audit/actions)
[![Downloads](https://img.shields.io/packagist/dt/phoenix1331/laravel-auth-audit)](https://packagist.org/packages/phoenix1331/laravel-auth-audit)

**Authorisation coverage reporting for Laravel. Larastan tells you your types are right. Auth Audit tells you your endpoints are actually protected.**

[Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) has been the #1 vulnerability on the OWASP Top 10 for multiple release cycles. The most common form in Laravel is [IDOR - Insecure Direct Object Reference](https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference) - and it is trivially easy to introduce without realising it.

A developer who adds `auth` middleware to a route has proved who the user is - not that they're allowed to see or edit that specific record. The gap between the two is where IDOR lives. A logged-in user walks `/users/1`, `/users/2`, `/users/3` in the address bar and the app resolves every one, because nothing ever checked whether that user is allowed to see each profile. Auth Audit is a Composer dev-dependency that statically scans your routes, controllers, Form Requests, and Policies to find exactly these gaps, reports them as a coverage percentage, and fails your CI build when coverage drops below a threshold you set.

<img width="838" height="444" alt="Laravel Auth Audit HTML Output" src="https://github.com/user-attachments/assets/ed788c79-f38e-4775-b5c7-8bb3da8e7ad7" />

---

## Quick start

```bash
composer require phoenix1331/laravel-auth-audit --dev
php artisan auth-audit:run
```

That is it. No configuration required. The command scans your route collection and prints a table.

For CI, add a minimum threshold:

```bash
php artisan auth-audit:run --min=90
```

The command exits with code `1` when coverage is below the threshold, `0` otherwise.

---

## How detection works

The detector runs four tiers in confidence order, stopping at the first signal it finds:

**Tier 1 - Middleware**
`can:` middleware on the route definition counts as an explicit authorisation signal. Custom middleware strings can be registered in `custom_signals` config to extend this tier.

**Tier 2 - Controller body (AST)**
The controller file is parsed as an AST using `nikic/php-parser` - the same library PHPStan and Rector use internally. The detector looks for `$this->authorize()`, `Gate::authorize()`, `Gate::allows()`, `Gate::check()`, `Gate::any()`, and `Gate::none()` inside the action method. A Form Request type-hint on the method signature is also inspected - if its `authorize()` method contains only `return true;`, it is flagged as the `bare-true-form-request` anti-pattern rather than counted as a signal.

**Tier 3 - Policy**
For each Eloquent model bound to the route via route-model binding, the detector checks whether a Policy is registered for that model and whether the policy has a method matching the implied CRUD action (`store` maps to `create`, `destroy` maps to `delete`, etc.).

**Tier 4 - Custom signals**
An escape hatch for teams whose authorisation lives in a service layer, a custom middleware, or another pattern the static detector cannot infer. Register the class method or middleware name in `custom_signals` config.

**Known limitation:** authorisation that lives inside a called service method is not visible to the static AST pass. If `AuthService::authorizeView()` internally calls `Gate::authorize()`, the detector sees only that `AuthService::authorizeView()` was called - it does not follow the call graph into the service. This is an honest known gap, not a bug; the roadmap section below describes the runtime detection tier that addresses it.

---

## CLI reference

```bash
# basic scan
php artisan auth-audit:run

# fail CI below 90% coverage
php artisan auth-audit:run --min=90

# machine-readable JSON output
php artisan auth-audit:run --json

# write a self-contained HTML report
php artisan auth-audit:run --html=storage/auth-audit/report.html

# compare against a previous JSON report for delta indicators
php artisan auth-audit:run --html=report.html --compare=previous-report.json
```

Sample console output:

```
  Route                          Verb   Auth Check           Status
  ---------------------------------------------------------------
  /orders/{order}                PUT    $this->authorize()   ✓ authorised
  /orders/{order}                DELETE -                    ✗ unauthorised
  /reports/export                GET    can:view-reports     ✓ authorised
  /webhooks/stripe               POST   Signature verified   - skipped
  ---------------------------------------------------------------
  Coverage: 82% (211/257 routes)
  18 unauthorised . 28 excluded . 13 skipped (+3 vs baseline)

  x Coverage 82% is below the configured minimum of 90%.
```

---

## Configuration

Publish the config file:

```bash
php artisan vendor:publish --tag=auth-audit-config
```

This creates `config/auth-audit.php`. The package works without publishing - defaults are merged automatically.

| Key | Type | Default | Purpose |
|---|---|---|---|
| `enabled` | bool | `true` | Global on/off switch |
| `min_coverage` | int | `80` | CI threshold - exit code 1 below this |
| `exclude` | array | auth/password routes | URI or route name patterns excluded from the scan |
| `exclude_middleware` | array | `['guest']` | Routes behind these middleware are excluded automatically |
| `scan_paths` | array | `app/Http/Controllers` | Directories walked for controller discovery |
| `custom_signals` | array | `[]` | Additional class methods or middleware that count as authorised |
| `flag_bare_true_form_requests` | bool | `true` | Flag `authorize() { return true; }` as a named anti-pattern |
| `html.output_path` | string | `storage/auth-audit/report.html` | Default path for `--html` output |
| `html.title` | string | `Auth Audit Report` | Report header text |
| `require_exclusion_reasons` | bool | `true` | Every `exclude` entry must carry a documented reason string |

The `require_exclusion_reasons` option is the anti-gaming mechanism. The HTML report always surfaces the full exclusion list with reasons - nothing is hidden.

---

## Bypassing the audit

Two colocated bypass mechanisms are available. Both require a mandatory reason string - silent suppression is not possible.

### Attribute

```php
use Phoenix1331\LaravelAuthAudit\Attributes\WithoutAuthAudit;

// on a specific action
#[WithoutAuthAudit('Signature verified via Stripe webhook secret, not policy-gated')]
public function stripe(): void { ... }

// on an entire controller
#[WithoutAuthAudit('Public marketing pages')]
class MarketingController extends Controller { ... }

// with an expiry date - past the date, the bypass reverts to a flagged violation automatically
#[WithoutAuthAudit('Policy not written yet', expires: '2026-12-31')]
public function betaExport(): void { ... }
```

The `expires` parameter is the key differentiator from `@SuppressWarnings`-style annotations elsewhere in the ecosystem. A temporary bypass cannot quietly become permanent technical debt.

### Route macro

```php
Route::get('/up', fn () => response()->json(['ok' => true]))
    ->name('health')
    ->withoutAuthAudit('Health check endpoint, no sensitive data, no auth required');
```

### Skip volume as a metric

Skip counts are reported separately from the coverage percentage, specifically so teams cannot game the headline number by skipping instead of fixing. A CI comment showing `+3 skips this PR` is a visible signal even when the coverage number looks fine.

### Custom signals

If your authorisation lives in a custom middleware, register it in config so the detector counts it correctly:

```php
// config/auth-audit.php
'custom_signals' => [
    'ensure.team.owner',
    'App\\Services\\TeamAuthService::authorize',
],
```

Without this entry the route appears red (false positive). With it, it appears green. The config is the documented contract for non-standard patterns.

---

## CI recipe

```yaml
- name: run auth audit
  run: php artisan auth-audit:run --min=90
```

To save the JSON as a baseline for delta comparison on the next run:

```yaml
- name: run auth audit
  run: php artisan auth-audit:run --min=90 --json > auth-audit-baseline.json

- name: upload baseline
  uses: actions/upload-artifact@v4
  with:
    name: auth-audit-baseline
    path: auth-audit-baseline.json
```

---

## Why we built this

Broken access control has been the number 1 issue on the OWASP Top 10 for multiple release cycles. The most recognisable instance in Laravel is IDOR - Insecure Direct Object Reference. A developer adds a route, wires up a controller, puts it behind `auth` middleware, and ships it. Nothing enforces that they also checked whether the authenticated user is allowed to access that specific record.

The result: any logged-in user walks `/users/1`, `/users/2`, `/users/3` and reads every profile in the system. The route looks secure at a glance - it sits behind `auth`, a Policy class even exists in the codebase - but nobody wired the Policy check to this route.

Existing tooling does not close this gap:

- Larastan and PHPStan catch type errors, not missing authorisation
- Enlightn covers general best practices but does not walk the route to controller to model graph specifically for authorisation coverage
- Spatie Laravel Permission gives you tools to build authorisation - it does not audit whether you used them correctly everywhere you needed to

Laravel Auth Audit sits in the gap. It does not invent a new authorisation concept. It audits whether the ones Laravel already ships with were actually applied.

References:
- OWASP A01:2021 Broken Access Control - owasp.org/Top10/2021/A01_2021-Broken_Access_Control
- OWASP IDOR attack pattern - owasp.org/www-community/attacks/Insecure_Direct_Object_Reference

---

## Roadmap

- **v2:** runtime detection tier - an opt-in middleware for staging environments that logs actual Gate and Policy invocations, reconciled against the static report to catch service-layer authorisation the AST pass cannot see
- **v2/v3:** optional in-app dashboard (Telescope/Pulse-style) as a new consumer of the existing `AuditReport` data model - historical trend charts across commits, no scanning logic duplicated
- **stretch:** a GitHub Action wrapper (`uses: phoenix1331/laravel-auth-audit-action@v1`) for zero-config CI adoption

---

## Contributing

Pull requests are welcome. To add a new detection signal:

1. Clone the repo and install dependencies:

```bash
git clone https://github.com/phoenix1331/laravel-auth-audit
cd laravel-auth-audit
composer install
```

2. The test suite uses Pest with Orchestra Testbench - no database required:

```bash
./vendor/bin/pest
```

3. Add a fixture controller in `tests/Fixtures/Controllers/` demonstrating the pattern
4. Add a unit test in `tests/Unit/AuthorisationDetectorTest.php` covering the new signal
5. Add a feature test in `tests/Feature/AuthAuditRunCommandTest.php` asserting end-to-end behaviour
6. Run `./vendor/bin/pint` before committing

Prerequisites: PHP 8.2+, Composer. `osv-scanner` is required for the pre-commit hook (`go install github.com/google/osv-scanner/cmd/osv-scanner@latest`).

---

## Licence

MIT - see [LICENSE](LICENSE).
