# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | Critical fixes only |

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Report security issues by emailing **darren@phoenix1331.co.uk**. Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The package version affected

You will receive an acknowledgement within 48 hours. If the issue is confirmed, a fix will be released as soon as possible and you will be credited in the changelog unless you prefer to remain anonymous.

## Scope

This package is a static analysis tool that reads your application's source files and route definitions at development or CI time. It does not execute controller or policy code, does not make network requests, and does not store any data beyond an optional local baseline JSON file you write yourself.

### Potential concerns

**Baseline file contents** - The `auth-audit-baseline.json` file records route signatures and anti-pattern names. It does not contain credentials, user data, or request payloads. Treat it like any other build artifact and avoid committing it if your route structure is sensitive.

**Dependency chain** - This package depends on `nikic/php-parser` for AST analysis. Keep your `composer.lock` up to date and use a tool like `osv-scanner` or `composer audit` to monitor for vulnerabilities in the dependency chain.

**False negatives** - The package reports routes it can verify are authorised. It does not guarantee that every authorisation check is correctly implemented. A route marked "authorised" means a recognised check was detected, not that the check is logically correct. Do not use this tool as a substitute for security review.

## Disclosure Policy

Once a fix is released, the vulnerability will be documented in `CHANGELOG.md` under the relevant version. We follow coordinated disclosure and will not publish details until a fix is available.
