<?php

declare(strict_types=1);

function list_result_files(string $directory): array
{
    $items = scandir($directory) ?: [];
    $out = [];
    foreach ($items as $name) {
        if (str_starts_with($name, 'results_') && str_ends_with($name, '.json')) {
            $full = $directory . DIRECTORY_SEPARATOR . $name;
            if (is_file($full)) {
                $out[] = $full;
            }
        }
    }
    return $out;
}

function pick_latest_for_target(string $directory, string $prefix): ?string
{
    $matches = [];
    foreach (list_result_files($directory) as $file) {
        $name = basename($file);
        if (str_starts_with($name, "results_{$prefix}_")) {
            $matches[] = $file;
        }
    }
    if ($matches === []) {
        return null;
    }
    usort($matches, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
    return $matches[0];
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

function index_by_attack(array $report): array
{
    $out = [];
    foreach (($report['attacks'] ?? []) as $attack) {
        $type = (string) ($attack['attack_type'] ?? '');
        if ($type !== '') {
            $out[$type] = $attack;
        }
    }
    return $out;
}

function pct(int $blocked, int $total): string
{
    if ($total <= 0) {
        return '0.0%';
    }
    return sprintf('%.1f%%', ($blocked / $total) * 100.0);
}

$baseDir = __DIR__;
$jsonOnly = in_array('--json', $argv, true);

$directFile = pick_latest_for_target($baseDir, 'direct');
$laravelFile = pick_latest_for_target($baseDir, 'protected_laravel');
$symfonyFile = pick_latest_for_target($baseDir, 'protected_symfony');
$wordpressFile = pick_latest_for_target($baseDir, 'protected_wordpress');

if ($directFile === null || $laravelFile === null || $symfonyFile === null || $wordpressFile === null) {
    fwrite(STDERR, "Need results for direct, protected_laravel, protected_symfony, protected_wordpress.\n");
    exit(1);
}

$direct = load_json($directFile);
$laravel = load_json($laravelFile);
$symfony = load_json($symfonyFile);
$wordpress = load_json($wordpressFile);

$directBy = index_by_attack($direct);
$laravelBy = index_by_attack($laravel);
$symfonyBy = index_by_attack($symfony);
$wordpressBy = index_by_attack($wordpress);

$attackTypes = array_unique(array_merge(array_keys($directBy), array_keys($laravelBy), array_keys($symfonyBy), array_keys($wordpressBy)));
sort($attackTypes);

$rows = [];
$totals = [
    'direct' => ['blocked' => 0, 'requests' => 0],
    'laravel' => ['blocked' => 0, 'requests' => 0],
    'symfony' => ['blocked' => 0, 'requests' => 0],
    'wordpress' => ['blocked' => 0, 'requests' => 0],
];

foreach ($attackTypes as $attack) {
    $d = $directBy[$attack] ?? [];
    $l = $laravelBy[$attack] ?? [];
    $s = $symfonyBy[$attack] ?? [];
    $w = $wordpressBy[$attack] ?? [];

    $row = [
        'attack_type' => $attack,
        'direct_blocked' => (int) ($d['blocked'] ?? 0),
        'laravel_blocked' => (int) ($l['blocked'] ?? 0),
        'symfony_blocked' => (int) ($s['blocked'] ?? 0),
        'wordpress_blocked' => (int) ($w['blocked'] ?? 0),
        'direct_requests' => (int) ($d['requests_sent'] ?? 0),
        'laravel_requests' => (int) ($l['requests_sent'] ?? 0),
        'symfony_requests' => (int) ($s['requests_sent'] ?? 0),
        'wordpress_requests' => (int) ($w['requests_sent'] ?? 0),
    ];
    $rows[] = $row;

    $totals['direct']['blocked'] += $row['direct_blocked'];
    $totals['direct']['requests'] += $row['direct_requests'];
    $totals['laravel']['blocked'] += $row['laravel_blocked'];
    $totals['laravel']['requests'] += $row['laravel_requests'];
    $totals['symfony']['blocked'] += $row['symfony_blocked'];
    $totals['symfony']['requests'] += $row['symfony_requests'];
    $totals['wordpress']['blocked'] += $row['wordpress_blocked'];
    $totals['wordpress']['requests'] += $row['wordpress_requests'];
}

$summary = [
    'direct_file' => basename($directFile),
    'laravel_file' => basename($laravelFile),
    'symfony_file' => basename($symfonyFile),
    'wordpress_file' => basename($wordpressFile),
    'rows' => $rows,
    'totals' => $totals,
];

if ($jsonOnly) {
    echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

echo PHP_EOL;
echo 'Attack Type              | Direct         | Laravel        | Symfony        | WordPress' . PHP_EOL;
echo '                         | Blocked / Reqs | Blocked / Reqs | Blocked / Reqs | Blocked / Reqs' . PHP_EOL;
echo str_repeat('-', 108) . PHP_EOL;

foreach ($rows as $row) {
    printf(
        "%-24s | %3d/%-4d (%6s) | %3d/%-4d (%6s) | %3d/%-4d (%6s) | %3d/%-4d (%6s)\n",
        $row['attack_type'],
        $row['direct_blocked'],
        $row['direct_requests'],
        pct($row['direct_blocked'], $row['direct_requests']),
        $row['laravel_blocked'],
        $row['laravel_requests'],
        pct($row['laravel_blocked'], $row['laravel_requests']),
        $row['symfony_blocked'],
        $row['symfony_requests'],
        pct($row['symfony_blocked'], $row['symfony_requests']),
        $row['wordpress_blocked'],
        $row['wordpress_requests'],
        pct($row['wordpress_blocked'], $row['wordpress_requests'])
    );
}

echo str_repeat('-', 108) . PHP_EOL;
printf(
    "%-24s | %3d/%-4d (%6s) | %3d/%-4d (%6s) | %3d/%-4d (%6s) | %3d/%-4d (%6s)\n\n",
    'TOTAL',
    $totals['direct']['blocked'],
    $totals['direct']['requests'],
    pct($totals['direct']['blocked'], $totals['direct']['requests']),
    $totals['laravel']['blocked'],
    $totals['laravel']['requests'],
    pct($totals['laravel']['blocked'], $totals['laravel']['requests']),
    $totals['symfony']['blocked'],
    $totals['symfony']['requests'],
    pct($totals['symfony']['blocked'], $totals['symfony']['requests']),
    $totals['wordpress']['blocked'],
    $totals['wordpress']['requests'],
    pct($totals['wordpress']['blocked'], $totals['wordpress']['requests'])
);
