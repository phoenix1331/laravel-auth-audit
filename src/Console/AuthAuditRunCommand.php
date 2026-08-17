<?php

namespace Phoenix1331\LaravelAuthAudit\Console;

use Illuminate\Console\Command;

class AuthAuditRunCommand extends Command
{
    protected $signature = 'auth-audit:run
                            {--min= : Minimum coverage percentage required (overrides config)}
                            {--json : Output results as JSON}
                            {--html= : Write a self-contained HTML report to this path}
                            {--compare= : Path to a previous JSON report for delta comparison}';

    protected $description = 'Scan Laravel routes for missing authorisation checks and report coverage';

    public function handle(): int
    {
        return self::SUCCESS;
    }
}
