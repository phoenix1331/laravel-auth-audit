# Upgrading Guide

## From 1.x to 2.0.0

Version 2.0.0 introduces deeper static analysis of controller bodies and policy methods. Some routes that were marked **authorised** in v1 will now be flagged as **unauthorised** or carry an anti-pattern warning. This is intentional - v2 catches classes of IDOR risk that v1 silently passed.

### What can flip from green to red

#### `unscoped-nested-binding`

A route with two or more route-model-bound parameters where neither `->scopeBindings()` is applied nor the child parameter follows Laravel's parent-child naming convention (`{team}/{team_order}`).

```php
// was: authorised (v1 saw $this->authorize() and stopped)
// now: unscoped-nested-binding (the Order is not scoped to the Team)
Route::get('/teams/{team}/orders/{order}', [OrderController::class, 'show']);
```

Fix: call `->scopeBindings()` on the route, or rename the child segment to follow the convention, or add an explicit ownership check in the controller body.

#### `class-level-check-on-instance-route`

An `authorize()` or `Gate::*` call that passes `Model::class` as the second argument on a route that has a bound model instance. The policy receives the class string, not the instance, so it cannot verify ownership.

```php
// was: authorised (v1 detected $this->authorize())
// now: class-level-check-on-instance-route
$this->authorize('update', Order::class); // wrong - should be $order
```

Fix: pass the bound instance instead of the class constant: `$this->authorize('update', $order)`.

#### `instance-blind-policy`

A policy method that either has no model parameter or never references it in its body. v1 only checked that the policy method existed. v2 parses the method body.

```php
// was: authorised (v1 found a matching policy method)
// now: instance-blind-policy
public function update(User $user): bool
{
    return $user->isAdmin(); // never checks which order is being accessed
}
```

Fix: add the model as a typed parameter and use it in the check.

#### `unbound-identifier`

A route with a raw scalar parameter (`{id}` without type-hinting to a model) where the controller calls `find()`, `findOrFail()`, `firstWhere()`, or `where('id', ...)` without first scoping to the authenticated user.

```php
// was: authorised or unchecked (v1 did not inspect the query)
// now: unbound-identifier
public function show(Request $request, int $id): Response
{
    $order = Order::findOrFail($id); // any user can access any order
}
```

Fix: scope the query to the authenticated user, or switch to route model binding with `->scopeBindings()`.

#### `discarded-gate-result`

`Gate::allows()`, `Gate::check()`, or `Gate::any()` called as a bare statement whose return value is never used.

```php
// was: authorised (v1 saw a Gate:: call)
// now: discarded-gate-result
Gate::allows('update', $order); // result discarded, check has no effect
```

Fix: wrap in `abort_unless()`, an `if` block, or `Gate::authorize()` instead.

---

### Adopting v2 incrementally with `--generate-baseline`

If you have a large application and cannot fix every flagged route immediately, use the baseline feature to record the current state and enforce "no regressions" in CI.

**Step 1 - Generate a baseline on your current codebase:**

```bash
php artisan auth-audit:run --generate-baseline
```

This writes `auth-audit-baseline.json` at your project root (configurable via `auth-audit.baseline_path` in `config/auth-audit.php`).

**Step 2 - Commit the baseline file** and update your CI command:

```bash
php artisan auth-audit:run --compare=auth-audit-baseline.json --min=80
```

Routes in the baseline are shown as `baselined` and excluded from the coverage percentage. New routes added after the baseline was generated must be authorised - they are not grandfathered in.

**Step 3 - Work through flagged routes** at your own pace. Each time you fix a route, regenerate the baseline to shrink it:

```bash
php artisan auth-audit:run --generate-baseline
```

When the baseline is empty (all violations resolved), you can remove the `--compare` flag and enforce full coverage.

---

### New configuration key

`config/auth-audit.php` now includes:

```php
'baseline_path' => base_path('auth-audit-baseline.json'),
```

If you published the config in v1, add this key manually. If you did not publish it, no action is needed.

### JSON output schema additions

The JSON formatter (`--json`) now includes two additional top-level keys:

```json
{
  "baselined_count": 3,
  "stale_baseline_count": 0
}
```

Update any tooling that parses the JSON output if it uses strict schema validation.
