<?php

namespace Phoenix1331\LaravelAuthAudit\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Routing\Router;
use Phoenix1331\LaravelAuthAudit\Baseline\BaselineWriter;
use Phoenix1331\LaravelAuthAudit\Data\AuditReport;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;
use Phoenix1331\LaravelAuthAudit\Formatters\ConsoleFormatter;
use Phoenix1331\LaravelAuthAudit\Formatters\HtmlFormatter;
use Phoenix1331\LaravelAuthAudit\Formatters\JsonFormatter;
use Phoenix1331\LaravelAuthAudit\Scanning\AttributeResolver;
use Phoenix1331\LaravelAuthAudit\Scanning\AuthorisationDetector;
use Phoenix1331\LaravelAuthAudit\Scanning\PolicyResolver;
use Phoenix1331\LaravelAuthAudit\Scanning\RouteScanner;

class AuthAuditRunCommand extends Command
{
    protected $signature = 'auth-audit:run
                            {--min= : Minimum coverage percentage required (overrides config)}
                            {--json : Output results as JSON}
                            {--html= : Write a self-contained HTML report to this path}
                            {--compare= : Path to a previous JSON report for delta comparison}
                            {--generate-baseline : Write current violations to baseline file and exit}';

    protected $description = 'Scan Laravel routes for missing authorisation checks and report coverage';

    public function handle(): int
    {
        if (! config('auth-audit.enabled', true)) {
            $this->line('  <fg=gray>auth-audit is disabled via config.</>');

            return self::SUCCESS;
        }

        $config = config('auth-audit', []);

        $scanner = new RouteScanner($this->laravel->make(Router::class), $config);
        $policyResolver = new PolicyResolver($this->laravel->make(Gate::class));
        $detector = new AuthorisationDetector($config, $policyResolver);
        $attributeResolver = new AttributeResolver;

        $entries = $scanner->scan();

        $entries = array_map(function (RouteEntry $entry) use ($attributeResolver, $detector): RouteEntry {
            $entry = $attributeResolver->resolve($entry);

            return $detector->detect($entry);
        }, $entries);

        $baselineWriter = new BaselineWriter;
        $baseline = $this->loadBaseline($config, $baselineWriter);
        $report = $this->buildReport($entries, $baseline);

        if ($this->option('generate-baseline')) {
            $this->writeBaseline($report, $config, $baselineWriter);

            return self::SUCCESS;
        }

        if ($this->option('json')) {
            $this->line((new JsonFormatter)->render($report));

            return $this->resolveExitCode($report, $config);
        }

        (new ConsoleFormatter)->render($report, $this->output);

        if ($htmlPath = $this->option('html')) {
            $this->writeHtmlReport($report, $config, $htmlPath);
        }

        $min = $this->resolveMinCoverage($config);

        if ($report->coveragePercentage < $min) {
            (new ConsoleFormatter)->renderThresholdFailure($report, $min, $this->output);

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /** @param RouteEntry[] $entries */
    private function buildReport(array $entries, ?array $baseline): AuditReport
    {
        $authorised = 0;
        $unauthorised = 0;
        $skipped = 0;
        $excluded = 0;

        foreach ($entries as $entry) {
            match ($entry->status) {
                RouteStatus::Authorised => $authorised++,
                RouteStatus::Unauthorised => $unauthorised++,
                RouteStatus::Skipped => $skipped++,
                RouteStatus::Partial => $authorised++,
            };
        }

        $scoreable = $authorised + $unauthorised;
        $coverage = $scoreable > 0 ? round(($authorised / $scoreable) * 100, 2) : 100.0;

        return new AuditReport(
            routes: $entries,
            totalRoutes: count($entries),
            authorisedCount: $authorised,
            unauthorisedCount: $unauthorised,
            skippedCount: $skipped,
            excludedCount: $excluded,
            coveragePercentage: $coverage,
            previousSkippedCount: $baseline !== null ? ($baseline['skipped_count'] ?? null) : null,
            previousCoveragePercentage: $baseline !== null ? ($baseline['coverage_percentage'] ?? null) : null,
        );
    }

    private function writeHtmlReport(AuditReport $report, array $config, string $path): void
    {
        $title = $config['html']['title'] ?? 'Auth Audit Report';
        $html = (new HtmlFormatter)->render($report, $title);

        $dir = dirname($path);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($path, $html);
        $this->line("  <info>HTML report written to {$path}</info>");
    }

    private function loadBaseline(array $config, BaselineWriter $writer): ?array
    {
        $path = $this->option('compare') ?? ($config['baseline_path'] ?? null);

        if ($path === null) {
            return null;
        }

        return $writer->load($path);
    }

    private function writeBaseline(AuditReport $report, array $config, BaselineWriter $writer): void
    {
        $path = $this->option('compare') ?? ($config['baseline_path'] ?? base_path('auth-audit-baseline.json'));
        $writer->write($report, $path);
        $this->line("  <info>Baseline written to {$path} ({$report->unauthorisedCount} violations recorded).</info>");
    }

    private function resolveMinCoverage(array $config): int
    {
        $option = $this->option('min');

        if ($option !== null) {
            return (int) $option;
        }

        return (int) ($config['min_coverage'] ?? 80);
    }

    private function resolveExitCode(AuditReport $report, array $config): int
    {
        $min = $this->resolveMinCoverage($config);

        return $report->coveragePercentage < $min ? self::FAILURE : self::SUCCESS;
    }
}
