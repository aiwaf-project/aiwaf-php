<?php

declare(strict_types=1);

function utc_iso(): string
{
    return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DATE_ATOM);
}

function now_ms(): int
{
    return (int) floor(hrtime(true) / 1_000_000);
}

function safe_run_id(): string
{
    return str_replace([':', '.'], '-', utc_iso());
}

function build_output_path(string $targetName, string $runId): string
{
    return __DIR__ . DIRECTORY_SEPARATOR . "results_{$targetName}_{$runId}.json";
}

function hash_to_octet(string $seed): int
{
    $h = 0;
    $chars = preg_split('//u', $seed, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    foreach ($chars as $ch) {
        $h = (($h << 5) - $h) + ord($ch);
        $h &= 0xFFFFFFFF;
    }
    $positive = abs((int) $h);
    return ($positive % 200) + 10;
}

function build_ip(string $base, string $seed, int $offset): string
{
    $octet = ((hash_to_octet($seed) + $offset) % 245) + 10;
    return $base . '.' . $octet;
}

function make_ip_generator(string $base, string $seed, int $startOffset): callable
{
    $counter = $startOffset;
    return static function () use ($base, $seed, &$counter): string {
        $ip = build_ip($base, $seed, $counter);
        $counter++;
        return $ip;
    };
}

function make_header_generator(array $staticHeaders, ?callable $ipGenerator): callable
{
    return static function (string $_method, string $_url) use ($staticHeaders, $ipGenerator): array {
        $headers = $staticHeaders;
        if ($ipGenerator !== null) {
            $headers['x-forwarded-for'] = $ipGenerator();
        }
        return $headers;
    };
}

function request_once(string $method, string $url, array $headers = [], $body = null, ?callable $defaultHeadersProvider = null): array
{
    $start = now_ms();
    $status = 0;
    $error = null;

    $mergedHeaders = [];
    if ($defaultHeadersProvider !== null) {
        $mergedHeaders = (array) $defaultHeadersProvider($method, $url);
    }
    foreach ($headers as $k => $v) {
        $mergedHeaders[$k] = $v;
    }

    $curlHeaders = [];
    foreach ($mergedHeaders as $k => $v) {
        $curlHeaders[] = $k . ': ' . $v;
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    if ($curlHeaders !== []) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
    }

    if ($body !== null) {
        if (is_array($body) || is_object($body)) {
            $encoded = json_encode($body);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $encoded === false ? '{}' : $encoded);
            if (!isset($mergedHeaders['content-type']) && !isset($mergedHeaders['Content-Type'])) {
                $curlHeaders[] = 'content-type: application/json';
                curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
            }
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, (string) $body);
        }
    }

    $result = curl_exec($ch);
    if ($result === false) {
        $status = 0;
        $error = curl_error($ch) ?: 'request_failed';
    } else {
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    }
    if (PHP_VERSION_ID < 80500) {
        curl_close($ch);
    }

    $end = now_ms();
    return [
        'status' => $status,
        'duration_ms' => ($end - $start),
        'error' => $error,
    ];
}

function summarize(array $results): array
{
    $statusCounts = [];
    $totalDuration = 0;
    $blocked = 0;
    $errors = 0;
    $count = count($results);

    foreach ($results as $r) {
        $status = (int) ($r['status'] ?? 0);
        $duration = (int) ($r['duration_ms'] ?? 0);
        $key = (string) $status;
        $statusCounts[$key] = ($statusCounts[$key] ?? 0) + 1;
        $totalDuration += $duration;
        if (in_array($status, [403, 405, 409, 429], true)) {
            $blocked++;
        }
        if ($status === 0) {
            $errors++;
        }
    }

    return [
        'statusCounts' => $statusCounts,
        'blocked' => $blocked,
        'avgResponseTime' => $count > 0 ? ($totalDuration / $count) : 0,
        'errors' => $errors,
    ];
}

function delay_ms(int $ms): void
{
    usleep(max(0, $ms) * 1000);
}

function concurrent_requests(array $reqs, ?callable $defaultHeadersProvider): array
{
    $mh = curl_multi_init();
    $handles = [];
    $meta = [];

    foreach ($reqs as $i => $req) {
        [$method, $url, $headers, $body] = $req;
        $merged = $defaultHeadersProvider ? (array) $defaultHeadersProvider($method, $url) : [];
        foreach ($headers as $k => $v) {
            $merged[$k] = $v;
        }

        $curlHeaders = [];
        foreach ($merged as $k => $v) {
            $curlHeaders[] = $k . ': ' . $v;
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        if ($curlHeaders !== []) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
        }

        if ($body !== null) {
            if (is_array($body) || is_object($body)) {
                $encoded = json_encode($body);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $encoded === false ? '{}' : $encoded);
                if (!isset($merged['content-type']) && !isset($merged['Content-Type'])) {
                    $curlHeaders[] = 'content-type: application/json';
                    curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
                }
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, (string) $body);
            }
        }

        $handles[$i] = $ch;
        $meta[$i] = ['start' => now_ms()];
        curl_multi_add_handle($mh, $ch);
    }

    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh);
    } while ($running > 0);

    $results = [];
    foreach ($handles as $i => $ch) {
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        $results[] = [
            'status' => $error !== '' ? 0 : $status,
            'duration_ms' => now_ms() - (int) $meta[$i]['start'],
            'error' => $error !== '' ? $error : null,
        ];
        curl_multi_remove_handle($mh, $ch);
        if (PHP_VERSION_ID < 80500) {
            curl_close($ch);
        }
    }

    curl_multi_close($mh);
    return $results;
}

function attack_brute_force(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $results = [];
    $url = rtrim($baseUrl, '/') . '/rest/user/login';
    for ($i = 0; $i < 50; $i++) {
        $results[] = request_once('POST', $url, ['content-type' => 'application/json'], [
            'email' => "admin{$i}@example.com",
            'password' => 'password',
        ], $defaultHeadersProvider);
    }
    return $results;
}

function attack_credential_stuffing(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $results = [];
    $url = rtrim($baseUrl, '/') . '/rest/user/login';
    $candidates = [
        ['email' => 'admin@juice-sh.op', 'password' => 'admin123'],
        ['email' => 'admin@juice-sh.op', 'password' => 'password'],
        ['email' => 'test@juice-sh.op', 'password' => 'test'],
        ['email' => 'demo@juice-sh.op', 'password' => 'demo'],
    ];
    foreach ($candidates as $cred) {
        for ($i = 0; $i < 10; $i++) {
            $results[] = request_once('POST', $url, ['content-type' => 'application/json'], $cred, $defaultHeadersProvider);
        }
    }
    return $results;
}

function attack_path_probe(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $paths = ['/admin.php', '/.env', '/.git/config', '/../etc/passwd', '/wp-login.php', '/phpmyadmin', '/config.php', '/server-status', '/actuator/env', '/api/internal', '/backup.zip', '/.well-known/security.txt'];
    $out = [];
    foreach ($paths as $p) {
        $out[] = request_once('GET', rtrim($baseUrl, '/') . $p, [], null, $defaultHeadersProvider);
    }
    return $out;
}

function attack_header_probe(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    return [request_once('GET', rtrim($baseUrl, '/') . '/', [
        'user-agent' => 'sqlmap/1.0',
        'x-evil-header' => '1',
        'x-forwarded-for' => '127.0.0.1',
    ], null, $defaultHeadersProvider)];
}

function attack_header_variations(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $uas = ['sqlmap/1.8', 'nikto/2.5.0', 'masscan/1.3', 'curl/7.88.1', 'python-requests/2.31.0'];
    $out = [];
    foreach ($uas as $ua) {
        $out[] = request_once('GET', rtrim($baseUrl, '/') . '/', ['user-agent' => $ua, 'x-evil-header' => '1'], null, $defaultHeadersProvider);
    }
    return $out;
}

function attack_burst(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $reqs = [];
    $url = rtrim($baseUrl, '/') . '/';
    for ($i = 0; $i < 30; $i++) {
        $reqs[] = ['GET', $url, [], null];
    }
    return concurrent_requests($reqs, $defaultHeadersProvider);
}

function attack_burst_mixed(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $urls = [rtrim($baseUrl, '/') . '/', rtrim($baseUrl, '/') . '/rest/products', rtrim($baseUrl, '/') . '/rest/user/login'];
    $reqs = [];
    for ($i = 0; $i < 40; $i++) {
        $url = $urls[$i % count($urls)];
        if (str_ends_with($url, '/login')) {
            $reqs[] = ['POST', $url, ['content-type' => 'application/json'], ['email' => "burst{$i}@example.com", 'password' => 'x']];
        } else {
            $reqs[] = ['GET', $url, [], null];
        }
    }
    return concurrent_requests($reqs, $defaultHeadersProvider);
}

function attack_method_probe(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $root = rtrim($baseUrl, '/') . '/api/';
    return [
        request_once('PUT', $root, [], null, $defaultHeadersProvider),
        request_once('DELETE', $root, [], null, $defaultHeadersProvider),
        request_once('PATCH', $root, [], null, $defaultHeadersProvider),
    ];
}

function attack_query_injection(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $payloads = [
        "/rest/products/search?q=' OR 1=1--",
        '/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
        '/rest/products/search?q=%27%3BWAITFOR%20DELAY%20%270:0:3%27--',
    ];
    $out = [];
    foreach ($payloads as $p) {
        $out[] = request_once('GET', rtrim($baseUrl, '/') . $p, [], null, $defaultHeadersProvider);
    }
    return $out;
}

function attack_owasp_top10(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $reqs = [
        ['GET', "/rest/products/search?q=' OR 1=1--", [], null],
        ['GET', '/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', [], null],
        ['GET', '/rest/products/search?q=%7B%22$ne%22:%20null%7D', [], null],
        ['GET', '/api/Users?filter=__proto__', [], null],
        ['GET', '/api/Users?filter=%7B%22where%22:%7B%22id%22:1%7D%7D', [], null],
        ['GET', '/rest/user/whoami', [], null],
        ['GET', '/admin', [], null],
        ['GET', '/.env', [], null],
        ['GET', '/.git/config', [], null],
        ['GET', '/swagger.json', [], null],
        ['GET', '/api-docs', [], null],
        ['GET', '/rest/products/1/reviews', [], null],
        ['GET', '/rest/products/search?q=%2e%2e%2f%2e%2e%2fetc%2fpasswd', [], null],
        ['GET', '/rest/user/login?email=admin@juice-sh.op&password=admin123', [], null],
        ['POST', '/rest/user/login', ['content-type' => 'application/json'], ['email' => 'admin@juice-sh.op', 'password' => 'admin123']],
        ['POST', '/rest/user/login', ['content-type' => 'application/json'], ['email' => "admin@juice-sh.op' OR 1=1--", 'password' => 'x']],
    ];

    $out = [];
    foreach ($reqs as [$m, $p, $h, $b]) {
        $out[] = request_once($m, rtrim($baseUrl, '/') . $p, $h, $b, $defaultHeadersProvider);
    }
    return $out;
}

function attack_long_path(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $longPath = '/' . str_repeat('a', 2047);
    return [request_once('GET', rtrim($baseUrl, '/') . $longPath, [], null, $defaultHeadersProvider)];
}

function attack_normal_traffic(string $baseUrl, ?callable $defaultHeadersProvider): array
{
    $results = [];
    $h = [
        'user-agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36',
        'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language' => 'en-US,en;q=0.9',
        'accept-encoding' => 'gzip, deflate, br',
        'connection' => 'keep-alive',
    ];

    $paths = ['/', '/rest/products', '/rest/products/search?q=apple', '/api/Products/1', '/rest/user/whoami', '/api/BasketItems'];
    foreach ($paths as $p) {
        $results[] = request_once('GET', rtrim($baseUrl, '/') . $p, $h, null, $defaultHeadersProvider);
        delay_ms(50);
    }

    $uas = [
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
    ];
    foreach ($uas as $ua) {
        $hx = $h;
        $hx['user-agent'] = $ua;
        $results[] = request_once('GET', rtrim($baseUrl, '/') . '/', $hx, null, $defaultHeadersProvider);
        delay_ms(50);
        $results[] = request_once('GET', rtrim($baseUrl, '/') . '/rest/products', $hx, null, $defaultHeadersProvider);
        delay_ms(50);
    }

    return $results;
}

function run_test_suite(string $baseUrl, string $targetName, string $outputFile, array $tests, callable $headersProvider): array
{
    $health = request_once('GET', rtrim($baseUrl, '/') . '/', [], null, $headersProvider);
    if ((int) $health['status'] === 0) {
        $reason = !empty($health['error']) ? ' (' . $health['error'] . ')' : '';
        throw new RuntimeException("Unable to reach {$baseUrl}{$reason}. Is it running and reachable?");
    }

    $runId = basename($outputFile, '.json');
    $runId = str_replace('results_', '', $runId);

    $report = [
        'target' => $targetName,
        'baseUrl' => $baseUrl,
        'runId' => $runId,
        'startedAt' => utc_iso(),
        'attacks' => [],
    ];

    foreach ($tests as [$attackName, $attackFn]) {
        $results = $attackFn($baseUrl, $headersProvider);
        $summary = summarize($results);
        $report['attacks'][] = [
            'attack_type' => $attackName,
            'requests_sent' => count($results),
            'status_counts' => $summary['statusCounts'],
            'blocked' => $summary['blocked'],
            'errors' => $summary['errors'],
            'avg_response_time_ms' => $summary['avgResponseTime'],
        ];
    }

    $report['finishedAt'] = utc_iso();
    file_put_contents($outputFile, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    echo "Saved {$outputFile}" . PHP_EOL;

    return $report;
}

function run_normal_traffic_only(string $baseUrl, string $targetName, string $outputFile, callable $headers): array
{
    return run_test_suite($baseUrl, $targetName, $outputFile, [['normal_traffic', 'attack_normal_traffic']], $headers);
}

function run_attacks_suite(string $baseUrl, string $targetName, string $outputFile, callable $headers): array
{
    $tests = [
        ['brute_force', 'attack_brute_force'],
        ['credential_stuffing', 'attack_credential_stuffing'],
        ['path_probe', 'attack_path_probe'],
        ['header_probe', 'attack_header_probe'],
        ['header_variations', 'attack_header_variations'],
        ['burst', 'attack_burst'],
        ['burst_mixed', 'attack_burst_mixed'],
        ['query_injection', 'attack_query_injection'],
        ['owasp_top10', 'attack_owasp_top10'],
        ['long_path', 'attack_long_path'],
        ['method_probe', 'attack_method_probe'],
    ];
    return run_test_suite($baseUrl, $targetName, $outputFile, $tests, $headers);
}

function run_default_comparison(): void
{
    $runId = safe_run_id();
    $runSeed = 'run-' . $runId;

    $targets = [
        ['name' => 'direct', 'url' => 'http://localhost:3001'],
        ['name' => 'protected_laravel', 'url' => 'http://localhost:8081'],
        ['name' => 'protected_symfony', 'url' => 'http://localhost:8082'],
        ['name' => 'protected_wordpress', 'url' => 'http://localhost:8083'],
    ];

    $all = ['normal' => [], 'attacks' => []];

    foreach ($targets as $i => &$target) {
        $target['normalIp'] = build_ip('198.51.100', $runSeed, $i);
        $target['attackIp'] = build_ip('203.0.113', $runSeed, $i + 50);
        $target['normalIpGenerator'] = make_ip_generator('198.51.100', $runSeed, $i + 100);
        $target['attackIpGenerator'] = make_ip_generator('203.0.113', $runSeed, $i + 200);
    }
    unset($target);

    foreach ($targets as $target) {
        echo PHP_EOL . 'Running normal traffic tests for ' . $target['name'] . '...' . PHP_EOL;
        $normalOutput = build_output_path($target['name'] . '_normal', $runId);
        $normalReport = run_normal_traffic_only(
            $target['url'],
            $target['name'],
            $normalOutput,
            make_header_generator([], null)
        );
        $all['normal'][] = $normalReport;

        echo PHP_EOL . 'Running attack tests for ' . $target['name'] . '...' . PHP_EOL;
        $attackOutput = build_output_path($target['name'] . '_attacks', $runId);
        $attackReport = run_attacks_suite(
            $target['url'],
            $target['name'],
            $attackOutput,
            make_header_generator(['x-forwarded-for' => $target['attackIp']], $target['attackIpGenerator'])
        );
        $all['attacks'][] = $attackReport;
    }

    $comparisonFile = __DIR__ . DIRECTORY_SEPARATOR . "comparison_modes_{$runId}.json";
    file_put_contents($comparisonFile, json_encode([
        'runId' => $runId,
        'generatedAt' => utc_iso(),
        'normal' => $all['normal'],
        'attacks' => $all['attacks'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    echo PHP_EOL . 'Saved comprehensive comparison: ' . $comparisonFile . PHP_EOL;
}

function parse_args(array $argv): array
{
    $baseUrl = null;
    $targetName = 'target';
    $mode = 'all';

    $positional = [];
    for ($i = 1; $i < count($argv); $i++) {
        $arg = $argv[$i];
        if (str_starts_with($arg, '--mode=')) {
            $mode = substr($arg, 7);
            continue;
        }
        if ($arg === '--mode' && isset($argv[$i + 1])) {
            $mode = $argv[$i + 1];
            $i++;
            continue;
        }
        $positional[] = $arg;
    }

    if (isset($positional[0])) {
        $baseUrl = $positional[0];
    }
    if (isset($positional[1])) {
        $targetName = $positional[1];
    }

    return [$baseUrl, $targetName, $mode];
}

[$baseUrl, $targetName, $mode] = parse_args($argv);

if ($baseUrl === null) {
    run_default_comparison();
    exit(0);
}

$runId = safe_run_id();
$outputFile = build_output_path($targetName . '_' . $mode, $runId);
$runSeed = $targetName . '-' . $runId;
$normalIp = build_ip('198.51.100', $runSeed, 1);
$attackIp = build_ip('203.0.113', $runSeed, 2);
$normalIpGen = make_ip_generator('198.51.100', $runSeed, 100);
$attackIpGen = make_ip_generator('203.0.113', $runSeed, 200);

if ($mode === 'normal') {
    run_normal_traffic_only($baseUrl, $targetName, $outputFile, make_header_generator([], null));
    exit(0);
}

if ($mode === 'attacks') {
    run_attacks_suite($baseUrl, $targetName, $outputFile, make_header_generator(['x-forwarded-for' => $attackIp], $attackIpGen));
    exit(0);
}

run_test_suite(
    $baseUrl,
    $targetName,
    $outputFile,
    [
        ['normal_traffic', 'attack_normal_traffic'],
        ['brute_force', 'attack_brute_force'],
        ['credential_stuffing', 'attack_credential_stuffing'],
        ['path_probe', 'attack_path_probe'],
        ['header_probe', 'attack_header_probe'],
        ['header_variations', 'attack_header_variations'],
        ['burst', 'attack_burst'],
        ['burst_mixed', 'attack_burst_mixed'],
        ['query_injection', 'attack_query_injection'],
        ['owasp_top10', 'attack_owasp_top10'],
        ['long_path', 'attack_long_path'],
        ['method_probe', 'attack_method_probe'],
    ],
    make_header_generator([], null)
);
