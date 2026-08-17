<?php

namespace Phoenix1331\LaravelAuthAudit\Formatters;

use Phoenix1331\LaravelAuthAudit\Data\AuditReport;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;

class HtmlFormatter
{
    public function render(AuditReport $report, string $title): string
    {
        $coverage = (int) round($report->coveragePercentage);
        $band = $this->coverageBand($coverage);
        $delta = $report->coverageDelta();
        $skippedDelta = $report->skippedDelta();

        $routeRows = $this->buildRouteRows($report->routes);
        $exclusionRows = $this->buildExclusionRows($report->routes);
        $deltaHtml = $this->buildDeltaHtml($delta, $skippedDelta);
        $generated = date('Y-m-d H:i:s');

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{$title}</title>
            <style>
                *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
                .header { background: #1e293b; border-bottom: 1px solid #334155; padding: 2rem; }
                .header h1 { font-size: 1.25rem; font-weight: 600; color: #94a3b8; letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 1rem; }
                .coverage-block { display: flex; align-items: baseline; gap: 1rem; }
                .coverage-number { font-size: 5rem; font-weight: 700; line-height: 1; }
                .coverage-number.green { color: #22c55e; }
                .coverage-number.amber { color: #f59e0b; }
                .coverage-number.red { color: #ef4444; }
                .coverage-meta { color: #64748b; font-size: 0.875rem; line-height: 1.8; }
                .delta { font-size: 1rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px; }
                .delta.positive { background: #14532d; color: #22c55e; }
                .delta.negative { background: #450a0a; color: #ef4444; }
                .delta.neutral { background: #1e293b; color: #64748b; }
                .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
                .section { margin-bottom: 2.5rem; }
                .section-title { font-size: 0.75rem; font-weight: 600; color: #64748b; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #1e293b; }
                .controls { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
                .search { background: #1e293b; border: 1px solid #334155; color: #e2e8f0; padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.875rem; width: 280px; }
                .search::placeholder { color: #475569; }
                .search:focus { outline: none; border-color: #6366f1; }
                .filter-btn { background: #1e293b; border: 1px solid #334155; color: #94a3b8; padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.75rem; cursor: pointer; }
                .filter-btn.active { background: #312e81; border-color: #6366f1; color: #a5b4fc; }
                table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
                th { text-align: left; padding: 0.625rem 0.75rem; color: #64748b; font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #1e293b; cursor: pointer; user-select: none; white-space: nowrap; }
                th:hover { color: #94a3b8; }
                th .sort-icon { margin-left: 0.25rem; opacity: 0.4; }
                th.sorted .sort-icon { opacity: 1; }
                td { padding: 0.625rem 0.75rem; border-bottom: 1px solid #0f172a; vertical-align: middle; }
                tr:hover td { background: #1e293b; }
                tr.hidden { display: none; }
                .badge { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 500; }
                .badge.authorised { background: #14532d; color: #22c55e; }
                .badge.unauthorised { background: #450a0a; color: #ef4444; }
                .badge.skipped { background: #1e293b; color: #64748b; }
                .badge.partial { background: #451a03; color: #f59e0b; }
                .method { font-family: monospace; font-size: 0.75rem; background: #1e293b; padding: 0.15rem 0.4rem; border-radius: 3px; color: #94a3b8; }
                .uri { font-family: monospace; color: #a5b4fc; }
                .signal { font-family: monospace; font-size: 0.75rem; color: #64748b; }
                .anti-pattern { font-family: monospace; font-size: 0.75rem; color: #f59e0b; }
                .skip-reason { font-size: 0.75rem; color: #475569; font-style: italic; }
                .empty { text-align: center; padding: 3rem; color: #475569; font-size: 0.875rem; }
                .exclusion-table td:first-child { font-family: monospace; color: #a5b4fc; font-size: 0.8125rem; }
                .expiry { font-size: 0.75rem; }
                .expiry.expired { color: #ef4444; }
                .expiry.future { color: #64748b; }
                .footer { text-align: center; padding: 2rem; color: #334155; font-size: 0.75rem; border-top: 1px solid #1e293b; margin-top: 2rem; }
            </style>
        </head>
        <body>
            <div class="header">
                <div style="max-width:1200px;margin:0 auto;">
                    <h1>{$title}</h1>
                    <div class="coverage-block">
                        <div class="coverage-number {$band}">{$coverage}%</div>
                        <div class="coverage-meta">
                            {$deltaHtml}
                            {$report->authorisedCount} of {$report->totalRoutes} routes authorised<br>
                            {$report->unauthorisedCount} unauthorised &middot; {$report->skippedCount} skipped &middot; {$report->excludedCount} excluded<br>
                            Generated {$generated}
                        </div>
                    </div>
                </div>
            </div>

            <div class="container">
                <div class="section">
                    <div class="section-title">Routes</div>
                    <div class="controls">
                        <input type="text" class="search" id="routeSearch" placeholder="Filter by URI, controller, signal..." oninput="filterRoutes()">
                        <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
                        <button class="filter-btn" onclick="setFilter('unauthorised', this)">Unauthorised</button>
                        <button class="filter-btn" onclick="setFilter('authorised', this)">Authorised</button>
                        <button class="filter-btn" onclick="setFilter('skipped', this)">Skipped</button>
                    </div>
                    <table id="routeTable">
                        <thead>
                            <tr>
                                <th onclick="sortTable(0)">URI <span class="sort-icon">↕</span></th>
                                <th onclick="sortTable(1)">Verb <span class="sort-icon">↕</span></th>
                                <th onclick="sortTable(2)">Controller <span class="sort-icon">↕</span></th>
                                <th onclick="sortTable(3)">Auth Signal <span class="sort-icon">↕</span></th>
                                <th onclick="sortTable(4)">Status <span class="sort-icon">↕</span></th>
                            </tr>
                        </thead>
                        <tbody id="routeBody">
                            {$routeRows}
                        </tbody>
                    </table>
                </div>

                <div class="section">
                    <div class="section-title">Exclusions &amp; Bypasses</div>
                    <table class="exclusion-table">
                        <thead>
                            <tr>
                                <th>URI</th>
                                <th>Verb</th>
                                <th>Reason</th>
                                <th>Expiry</th>
                            </tr>
                        </thead>
                        <tbody>
                            {$exclusionRows}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="footer">
                phoenix1331/laravel-auth-audit &middot; generated {$generated}
            </div>

            <script>
                let activeFilter = 'all';
                let sortCol = -1;
                let sortAsc = true;

                function filterRoutes() {
                    const q = document.getElementById('routeSearch').value.toLowerCase();
                    const rows = document.querySelectorAll('#routeBody tr');
                    rows.forEach(row => {
                        const status = row.dataset.status;
                        const text = row.textContent.toLowerCase();
                        const matchesFilter = activeFilter === 'all' || status === activeFilter;
                        const matchesSearch = q === '' || text.includes(q);
                        row.classList.toggle('hidden', !(matchesFilter && matchesSearch));
                    });
                }

                function setFilter(filter, btn) {
                    activeFilter = filter;
                    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    filterRoutes();
                }

                function sortTable(col) {
                    const tbody = document.getElementById('routeBody');
                    const rows = Array.from(tbody.querySelectorAll('tr'));
                    if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
                    rows.sort((a, b) => {
                        const aText = a.cells[col]?.textContent.trim() ?? '';
                        const bText = b.cells[col]?.textContent.trim() ?? '';
                        return sortAsc ? aText.localeCompare(bText) : bText.localeCompare(aText);
                    });
                    rows.forEach(r => tbody.appendChild(r));
                    document.querySelectorAll('th').forEach((th, i) => th.classList.toggle('sorted', i === col));
                }
            </script>
        </body>
        </html>
        HTML;
    }

    /** @param RouteEntry[] $routes */
    private function buildRouteRows(array $routes): string
    {
        $html = '';

        foreach ($routes as $entry) {
            $uri = htmlspecialchars('/'.$entry->uri);
            $method = htmlspecialchars($entry->method);
            $controller = htmlspecialchars($entry->controller ? class_basename($entry->controller).'@'.($entry->action ?? '') : '-');
            $signal = $this->buildSignalCell($entry);
            $status = $this->buildStatusBadge($entry);
            $statusValue = $entry->status->value;

            $html .= <<<HTML
                        <tr data-status="{$statusValue}">
                                <td class="uri">{$uri}</td>
                                <td><span class="method">{$method}</span></td>
                                <td class="signal">{$controller}</td>
                                <td>{$signal}</td>
                                <td>{$status}</td>
                            </tr>
                        HTML;
        }

        if ($html === '') {
            $html = '<tr><td colspan="5" class="empty">No routes found.</td></tr>';
        }

        return $html;
    }

    /** @param RouteEntry[] $routes */
    private function buildExclusionRows(array $routes): string
    {
        $html = '';

        foreach ($routes as $entry) {
            if ($entry->status !== RouteStatus::Skipped) {
                continue;
            }

            $uri = htmlspecialchars('/'.$entry->uri);
            $method = htmlspecialchars($entry->method);
            $reason = htmlspecialchars($entry->skipReason ?? '-');
            $expiry = $this->buildExpiryCell($entry);

            $html .= <<<HTML
                        <tr>
                                <td>{$uri}</td>
                                <td><span class="method">{$method}</span></td>
                                <td class="skip-reason">{$reason}</td>
                                <td>{$expiry}</td>
                            </tr>
                        HTML;
        }

        if ($html === '') {
            $html = '<tr><td colspan="4" class="empty">No exclusions or bypasses.</td></tr>';
        }

        return $html;
    }

    private function buildSignalCell(RouteEntry $entry): string
    {
        if ($entry->antiPattern !== null) {
            return '<span class="anti-pattern">'.htmlspecialchars($entry->antiPattern).'</span>';
        }

        if ($entry->detectedSignal !== null) {
            return '<span class="signal">'.htmlspecialchars($entry->detectedSignal).'</span>';
        }

        if ($entry->skipReason !== null) {
            return '<span class="skip-reason">'.htmlspecialchars($entry->skipReason).'</span>';
        }

        return '<span class="signal">-</span>';
    }

    private function buildStatusBadge(RouteEntry $entry): string
    {
        return match ($entry->status) {
            RouteStatus::Authorised => '<span class="badge authorised">✓ authorised</span>',
            RouteStatus::Unauthorised => '<span class="badge unauthorised">✗ unauthorised</span>',
            RouteStatus::Partial => '<span class="badge partial">~ partial</span>',
            RouteStatus::Skipped => '<span class="badge skipped">- skipped</span>',
        };
    }

    private function buildExpiryCell(RouteEntry $entry): string
    {
        return '-';
    }

    private function buildDeltaHtml(?float $delta, ?int $skippedDelta): string
    {
        if ($delta === null) {
            return '';
        }

        $sign = $delta >= 0 ? '+' : '';
        $class = $delta > 0 ? 'positive' : ($delta < 0 ? 'negative' : 'neutral');
        $value = $sign.number_format($delta, 1).'%';

        $skippedStr = '';
        if ($skippedDelta !== null && $skippedDelta !== 0) {
            $skippedSign = $skippedDelta > 0 ? '+' : '';
            $skippedStr = " &middot; skips {$skippedSign}{$skippedDelta}";
        }

        return "<span class=\"delta {$class}\">{$value}{$skippedStr} vs baseline</span><br>";
    }

    private function coverageBand(int $coverage): string
    {
        if ($coverage >= 80) {
            return 'green';
        }

        if ($coverage >= 60) {
            return 'amber';
        }

        return 'red';
    }
}
