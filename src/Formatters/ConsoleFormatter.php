<?php

namespace Phoenix1331\LaravelAuthAudit\Formatters;

use Illuminate\Console\OutputStyle;
use Phoenix1331\LaravelAuthAudit\Data\AuditReport;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;

class ConsoleFormatter
{
    public function render(AuditReport $report, OutputStyle $output): void
    {
        $rows = [];

        foreach ($report->routes as $entry) {
            $rows[] = [
                $this->formatUri($entry),
                $entry->method,
                $this->formatSignal($entry),
                $this->formatStatus($entry),
            ];
        }

        $output->table(
            ['Route', 'Verb', 'Auth Check', 'Status'],
            $rows,
        );

        $this->renderSummary($report, $output);
    }

    private function renderSummary(AuditReport $report, OutputStyle $output): void
    {
        $coverage = number_format($report->coveragePercentage, 0);

        $output->writeln('');
        $output->writeln("  Coverage: <comment>{$coverage}%</comment> ({$report->authorisedCount}/{$report->totalRoutes} routes)");

        $parts = ["{$report->unauthorisedCount} unauthorised", "{$report->excludedCount} excluded", "{$report->skippedCount} skipped"];

        if ($report->baselinedCount > 0) {
            $parts[] = "{$report->baselinedCount} baselined";
        }

        $output->writeln('  '.implode(' · ', $parts));

        if ($report->staleBaselineCount > 0) {
            $output->writeln('');
            $output->writeln("  <comment>{$report->staleBaselineCount} stale baseline entries detected. Run --generate-baseline to update.</comment>");
        }
    }

    public function renderThresholdFailure(AuditReport $report, int $min, OutputStyle $output): void
    {
        $coverage = number_format($report->coveragePercentage, 0);
        $output->writeln('');
        $output->writeln("  <error> x </error> Coverage {$coverage}% is below the configured minimum of {$min}%.");
    }

    private function formatUri(RouteEntry $entry): string
    {
        return '/'.$entry->uri;
    }

    private function formatSignal(RouteEntry $entry): string
    {
        if ($entry->status === RouteStatus::Skipped) {
            return $entry->skipReason ?? '-';
        }

        if ($entry->antiPattern !== null) {
            return $entry->antiPattern;
        }

        return $entry->detectedSignal ?? '-';
    }

    private function formatStatus(RouteEntry $entry): string
    {
        return match ($entry->status) {
            RouteStatus::Authorised => '<info>✓ authorised</info>',
            RouteStatus::Unauthorised => '<fg=red>✗ unauthorised</>',
            RouteStatus::Partial => '<comment>~ partial</comment>',
            RouteStatus::Skipped => '<fg=gray>- skipped</>',
            RouteStatus::Baselined => '<fg=gray>~ baselined</>',
        };
    }
}
