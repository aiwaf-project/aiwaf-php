<?php

declare(strict_types=1);

function list_comparison_files(string $directory): array
{
    $items = scandir($directory) ?: [];
    $out = [];
    foreach ($items as $name) {
        if (str_starts_with($name, 'comparison_modes_') && str_ends_with($name, '.json')) {
            $full = $directory . DIRECTORY_SEPARATOR . $name;
            if (is_file($full)) {
                $out[] = $full;
            }
        }
    }
    usort($out, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
    return $out;
}

function load_json(string $path): array
{
    $raw = file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException("Unable to read {$path}");
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function calculate_stats(array $report): array
{
    $attacks = (array) ($report['attacks'] ?? []);
    $totalRequests = 0;
    $totalBlocked = 0;
    $totalAvgMs = 0.0;

    foreach ($attacks as $attack) {
        $totalRequests += (int) ($attack['requests_sent'] ?? 0);
        $totalBlocked += (int) ($attack['blocked'] ?? 0);
        $totalAvgMs += (float) ($attack['avg_response_time_ms'] ?? 0.0);
    }

    $blockedPct = $totalRequests > 0 ? ($totalBlocked / $totalRequests) * 100.0 : 0.0;
    $avgResponse = count($attacks) > 0 ? ($totalAvgMs / count($attacks)) : 0.0;

    return [
        'total_requests' => $totalRequests,
        'total_blocked' => $totalBlocked,
        'blocked_pct' => $blockedPct,
        'avg_response_time' => $avgResponse,
    ];
}

$baseDir = __DIR__;
$files = list_comparison_files($baseDir);
if ($files === []) {
    fwrite(STDERR, "No comparison_modes_*.json found in examples/sandbox/.\n");
    exit(1);
}

$comparisonFile = $files[0];
$data = load_json($comparisonFile);
$normalReports = (array) ($data['normal'] ?? []);
$attackReports = (array) ($data['attacks'] ?? []);

echo PHP_EOL;
echo ' WAF Comparison: Normal vs Attack Traffic' . PHP_EOL;
echo ' Generated: ' . substr((string) ($data['generatedAt'] ?? ''), 0, 10) . PHP_EOL;
echo PHP_EOL;

echo 'Target                   | Normal Traffic       | Attack Traffic       | Status' . PHP_EOL;
echo '                         | Reqs    Blocked %    | Reqs    Blocked %    |' . PHP_EOL;
echo str_repeat('-', 90) . PHP_EOL;

$results = [];
foreach ($normalReports as $normalReport) {
    $target = (string) ($normalReport['target'] ?? '');
    if ($target === '') {
        continue;
    }

    $attackReport = null;
    foreach ($attackReports as $candidate) {
        if ((string) ($candidate['target'] ?? '') === $target) {
            $attackReport = $candidate;
            break;
        }
    }
    if ($attackReport === null) {
        continue;
    }

    $normalStats = calculate_stats($normalReport);
    $attackStats = calculate_stats($attackReport);
    $results[] = ['target' => $target, 'normal' => $normalStats, 'attacks' => $attackStats];

    $status = '';
    if ($normalStats['blocked_pct'] > 5.0) {
        $status = ' HIGH FALSE POS';
    } elseif ($attackStats['blocked_pct'] < 50.0) {
        $status = ' LOW DETECTION';
    }

    printf(
        "%-24s| %-5d %8s   | %-5d %8s   |%s\n",
        $target,
        $normalStats['total_requests'],
        sprintf('%.1f%%', $normalStats['blocked_pct']),
        $attackStats['total_requests'],
        sprintf('%.1f%%', $attackStats['blocked_pct']),
        $status
    );
}

echo PHP_EOL . str_repeat('=', 90) . PHP_EOL;
echo PHP_EOL . 'Detailed Breakdown:' . PHP_EOL;

foreach ($results as $result) {
    $target = strtoupper((string) $result['target']);
    $normal = $result['normal'];
    $attacks = $result['attacks'];

    echo PHP_EOL . $target . PHP_EOL;
    echo str_repeat('-', 50) . PHP_EOL;

    echo PHP_EOL . 'Normal Traffic:' . PHP_EOL;
    echo '  Total Requests: ' . $normal['total_requests'] . PHP_EOL;
    echo '  Blocked: ' . $normal['total_blocked'] . ' (' . sprintf('%.1f%%', $normal['blocked_pct']) . ')' . PHP_EOL;
    echo '  Avg Response Time: ' . sprintf('%.2fms', $normal['avg_response_time']) . PHP_EOL;

    echo PHP_EOL . 'Attack Traffic:' . PHP_EOL;
    echo '  Total Requests: ' . $attacks['total_requests'] . PHP_EOL;
    echo '  Blocked: ' . $attacks['total_blocked'] . ' (' . sprintf('%.1f%%', $attacks['blocked_pct']) . ')' . PHP_EOL;
    echo '  Avg Response Time: ' . sprintf('%.2fms', $attacks['avg_response_time']) . PHP_EOL;

    if ($normal['blocked_pct'] > 5.0) {
        echo PHP_EOL . '   WARNING: High false positive rate (' . sprintf('%.1f%%', $normal['blocked_pct']) . ' of normal traffic blocked)' . PHP_EOL;
    }
    if ($attacks['blocked_pct'] < 50.0) {
        echo PHP_EOL . '   WARNING: Low attack detection rate (' . sprintf('%.1f%%', $attacks['blocked_pct']) . ' of attacks blocked)' . PHP_EOL;
    }
}

echo PHP_EOL . PHP_EOL . 'Full report: ' . basename($comparisonFile) . PHP_EOL . PHP_EOL;
