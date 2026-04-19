<?php

declare(strict_types=1);

/**
 * Comprehensive verification runner:
 * 1) PHPUnit suite
 * 2) Docker sandbox bring-up
 * 3) Attack/normal traffic suite
 * 4) Result threshold checks
 */

function out(string $text): void
{
    fwrite(STDOUT, $text . PHP_EOL);
}

function err(string $text): void
{
    fwrite(STDERR, $text . PHP_EOL);
}

function commandExists(string $command): bool
{
    $isWindows = DIRECTORY_SEPARATOR === '\\';
    $probe = $isWindows ? "where {$command}" : "command -v {$command}";
    exec($probe, $output, $exitCode);
    return $exitCode === 0;
}

function runCmd(array $cmd, ?string $cwd = null): int
{
    $parts = [];
    foreach ($cmd as $part) {
        $parts[] = escapeshellarg($part);
    }
    $command = implode(' ', $parts);

    $descriptors = [
        0 => STDIN,
        1 => STDOUT,
        2 => STDERR,
    ];

    $proc = proc_open($command, $descriptors, $pipes, $cwd ?? null);
    if (!is_resource($proc)) {
        throw new RuntimeException('Failed to start command: ' . $command);
    }

    return proc_close($proc);
}

function dumpComposeDiagnostics(string $composeFile, string $root): void
{
    err('==> Compose diagnostics');
    runCmd(['docker', 'compose', '-f', $composeFile, 'ps'], $root);
    runCmd(['docker', 'compose', '-f', $composeFile, 'logs', '--no-color', '--tail', '150'], $root);
}

/**
 * @return array<int, string>
 */
function findContainerIdsByName(string $pattern): array
{
    $command = 'docker ps -aq --filter ' . escapeshellarg('name=' . $pattern);
    exec($command, $output, $exitCode);
    if ($exitCode !== 0) {
        return [];
    }

    $ids = [];
    foreach ($output as $line) {
        $id = trim($line);
        if ($id !== '') {
            $ids[] = $id;
        }
    }

    return array_values(array_unique($ids));
}

function cleanupStaleSandboxContainers(string $root): void
{
    $patterns = [
        'sandbox-aiwaf-',
        '_sandbox-aiwaf-',
        'sandbox-juice-1',
    ];

    $allIds = [];
    foreach ($patterns as $pattern) {
        $allIds = array_merge($allIds, findContainerIdsByName($pattern));
    }
    $allIds = array_values(array_unique($allIds));

    if ($allIds === []) {
        return;
    }

    out('==> Removing stale sandbox containers (' . count($allIds) . ')');
    runCmd(array_merge(['docker', 'rm', '-f'], $allIds), $root);
}

function canConnectHttp(string $url, int $timeoutSeconds = 2): bool
{
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => $timeoutSeconds,
            'ignore_errors' => true,
        ],
    ]);

    $fh = @fopen($url, 'rb', false, $context);
    if ($fh === false) {
        return false;
    }

    fclose($fh);
    return true;
}

/**
 * @param array<int, string> $urls
 */
function waitForHttpTargets(array $urls, int $maxWaitSeconds = 120): bool
{
    $deadline = time() + $maxWaitSeconds;

    while (time() <= $deadline) {
        $allReady = true;
        foreach ($urls as $url) {
            if (!canConnectHttp($url, 2)) {
                $allReady = false;
                break;
            }
        }

        if ($allReady) {
            return true;
        }

        usleep(500000);
    }

    return false;
}

function listFilesByPrefix(string $directory, string $prefix): array
{
    $items = scandir($directory) ?: [];
    $files = [];
    foreach ($items as $item) {
        if (str_starts_with($item, $prefix) && str_ends_with($item, '.json')) {
            $full = $directory . DIRECTORY_SEPARATOR . $item;
            if (is_file($full)) {
                $files[] = $full;
            }
        }
    }

    usort($files, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
    return $files;
}

function loadJson(string $file): array
{
    $raw = file_get_contents($file);
    if ($raw === false) {
        throw new RuntimeException('Unable to read file: ' . $file);
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('Invalid JSON in file: ' . $file);
    }

    return $decoded;
}

function calcStats(array $report): array
{
    $attacks = (array) ($report['attacks'] ?? []);
    $totalRequests = 0;
    $totalBlocked = 0;

    foreach ($attacks as $attack) {
        $totalRequests += (int) ($attack['requests_sent'] ?? 0);
        $totalBlocked += (int) ($attack['blocked'] ?? 0);
    }

    $blockedPct = $totalRequests > 0 ? ($totalBlocked / $totalRequests) * 100.0 : 0.0;

    return [
        'total_requests' => $totalRequests,
        'total_blocked' => $totalBlocked,
        'blocked_pct' => $blockedPct,
    ];
}

function reportByTarget(array $reports): array
{
    $indexed = [];
    foreach ($reports as $report) {
        $target = (string) ($report['target'] ?? '');
        if ($target !== '') {
            $indexed[$target] = $report;
        }
    }
    return $indexed;
}

function parseArgs(array $argv): array
{
    $options = [
        'keep-up' => false,
        'skip-docker' => false,
        'reset-state' => true,
        'compose-retries' => 2,
        'build-sandbox' => false,
        'max-normal-block-pct' => 5.0,
        'min-protected-attack-block-pct' => 80.0,
        'max-direct-attack-block-pct' => 15.0,
        'max-protected-parity-gap-pct' => 1.0,
    ];

    foreach ($argv as $arg) {
        if ($arg === '--keep-up') {
            $options['keep-up'] = true;
            continue;
        }
        if ($arg === '--skip-docker') {
            $options['skip-docker'] = true;
            continue;
        }
        if ($arg === '--no-reset-state') {
            $options['reset-state'] = false;
            continue;
        }
        if ($arg === '--build-sandbox') {
            $options['build-sandbox'] = true;
            continue;
        }

        if (str_starts_with($arg, '--max-normal-block-pct=')) {
            $options['max-normal-block-pct'] = (float) substr($arg, strlen('--max-normal-block-pct='));
            continue;
        }
        if (str_starts_with($arg, '--min-protected-attack-block-pct=')) {
            $options['min-protected-attack-block-pct'] = (float) substr($arg, strlen('--min-protected-attack-block-pct='));
            continue;
        }
        if (str_starts_with($arg, '--max-direct-attack-block-pct=')) {
            $options['max-direct-attack-block-pct'] = (float) substr($arg, strlen('--max-direct-attack-block-pct='));
            continue;
        }
        if (str_starts_with($arg, '--max-protected-parity-gap-pct=')) {
            $options['max-protected-parity-gap-pct'] = (float) substr($arg, strlen('--max-protected-parity-gap-pct='));
            continue;
        }
        if (str_starts_with($arg, '--compose-retries=')) {
            $options['compose-retries'] = max(1, (int) substr($arg, strlen('--compose-retries=')));
            continue;
        }
    }

    return $options;
}

function main(array $argv): int
{
    $root = dirname(__DIR__);
    $sandboxDir = $root . DIRECTORY_SEPARATOR . 'examples' . DIRECTORY_SEPARATOR . 'sandbox';
    $composeFile = $sandboxDir . DIRECTORY_SEPARATOR . 'docker-compose.yml';
    $options = parseArgs(array_slice($argv, 1));

    if (!is_file($composeFile)) {
        err('Compose file not found: ' . $composeFile);
        return 2;
    }

    if (!commandExists('docker')) {
        err('docker command is required for sandbox verification.');
        return 2;
    }

    $phpBin = PHP_BINARY;
    $failed = false;

    out('==> Step 1/4: PHPUnit');
    $phpunitExit = runCmd([$phpBin, 'vendor/bin/phpunit', '--colors=never', '--do-not-cache-result'], $root);
    if ($phpunitExit !== 0) {
        err('PHPUnit failed.');
        return 1;
    }

    if (!$options['skip-docker']) {
        out('==> Step 2/4: Start sandbox containers');

        if ($options['reset-state']) {
            out('==> Reset sandbox state (down -v)');
            runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);
            cleanupStaleSandboxContainers($root);
            usleep(1200000);
        }

        $upExit = 1;
        $composeRetries = (int) $options['compose-retries'];
        for ($attempt = 1; $attempt <= $composeRetries; $attempt++) {
            out(sprintf('==> Compose up attempt %d/%d', $attempt, $composeRetries));
            cleanupStaleSandboxContainers($root);

            $juiceCmd = ['docker', 'compose', '-f', $composeFile, 'up', '-d', '--remove-orphans'];
            if ((bool) $options['build-sandbox']) {
                $juiceCmd[] = '--build';
            }
            $juiceCmd[] = 'juice';

            $upExit = runCmd($juiceCmd, $root);
            if ($upExit !== 0) {
                err('Failed to start juice service on this attempt.');
                dumpComposeDiagnostics($composeFile, $root);
                runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);
                cleanupStaleSandboxContainers($root);
                usleep(1200000);
                continue;
            }

            $readyJuice = waitForHttpTargets(['http://localhost:3001'], 120);
            if (!$readyJuice) {
                err('Juice did not become reachable in time.');
                dumpComposeDiagnostics($composeFile, $root);
                runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);
                cleanupStaleSandboxContainers($root);
                usleep(1200000);
                continue;
            }

            $upCmd = ['docker', 'compose', '-f', $composeFile, 'up', '-d', '--remove-orphans'];
            if ((bool) $options['build-sandbox']) {
                $upCmd[] = '--build';
            }
            $upCmd[] = 'aiwaf-laravel-php81';
            $upCmd[] = 'aiwaf-symfony-php82';
            $upCmd[] = 'aiwaf-wordpress-php80';

            $upExit = runCmd($upCmd, $root);
            if ($upExit === 0) {
                break;
            }

            err('Compose up failed on this attempt.');
            dumpComposeDiagnostics($composeFile, $root);
            runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);
            cleanupStaleSandboxContainers($root);
            usleep(1200000);
        }

        if ($upExit !== 0) {
            err('Failed to bring up sandbox containers.');
            return 1;
        }

        out('==> Waiting for sandbox HTTP endpoints');
        $ready = waitForHttpTargets([
            'http://localhost:3001',
            'http://localhost:8081',
            'http://localhost:8082',
            'http://localhost:8083',
        ], 150);

        if (!$ready) {
            err('Sandbox endpoints did not become reachable in time.');
            dumpComposeDiagnostics($composeFile, $root);
            return 1;
        }
    } else {
        out('==> Step 2/4: Skipped docker compose up (requested)');
    }

    try {
        out('==> Step 3/4: Run sandbox traffic suite');
        $attackExit = runCmd([$phpBin, 'attack-suite.php'], $sandboxDir);
        if ($attackExit !== 0) {
            err('attack-suite.php failed on first attempt; retrying once after brief wait.');
            usleep(1500000);
            $attackExit = runCmd([$phpBin, 'attack-suite.php'], $sandboxDir);
        }
        if ($attackExit !== 0) {
            err('attack-suite.php failed.');
            $failed = true;
        }

        out('==> Step 4/4: Evaluate results');
        $comparisonFiles = listFilesByPrefix($sandboxDir, 'comparison_modes_');
        if ($comparisonFiles === []) {
            throw new RuntimeException('No comparison_modes_*.json file found.');
        }

        $comparison = loadJson($comparisonFiles[0]);
        $normalByTarget = reportByTarget((array) ($comparison['normal'] ?? []));
        $attacksByTarget = reportByTarget((array) ($comparison['attacks'] ?? []));

        $requiredTargets = ['direct', 'protected_laravel', 'protected_symfony', 'protected_wordpress'];
        foreach ($requiredTargets as $target) {
            if (!isset($normalByTarget[$target])) {
                throw new RuntimeException('Missing normal report for target: ' . $target);
            }
            if (!isset($attacksByTarget[$target])) {
                throw new RuntimeException('Missing attack report for target: ' . $target);
            }
        }

        $directAttack = calcStats($attacksByTarget['direct']);
        $protectedTargets = ['protected_laravel', 'protected_symfony', 'protected_wordpress'];

        out('Summary thresholds:');
        out('  max normal blocked %: ' . $options['max-normal-block-pct']);
        out('  min protected attack blocked %: ' . $options['min-protected-attack-block-pct']);
        out('  max direct attack blocked %: ' . $options['max-direct-attack-block-pct']);
        out('  max protected parity gap %: ' . $options['max-protected-parity-gap-pct']);

        $protectedAttackPcts = [];
        foreach ($requiredTargets as $target) {
            $normal = calcStats($normalByTarget[$target]);
            $attacks = calcStats($attacksByTarget[$target]);
            $label = strtoupper($target);

            out(sprintf(
                '%s normal %.1f%% (%d/%d) | attacks %.1f%% (%d/%d)',
                $label,
                $normal['blocked_pct'],
                $normal['total_blocked'],
                $normal['total_requests'],
                $attacks['blocked_pct'],
                $attacks['total_blocked'],
                $attacks['total_requests']
            ));

            if ($normal['blocked_pct'] > $options['max-normal-block-pct']) {
                err("FAIL: {$target} normal blocked % above threshold.");
                $failed = true;
            }

            if ($target !== 'direct') {
                if ($attacks['blocked_pct'] < $options['min-protected-attack-block-pct']) {
                    err("FAIL: {$target} attack blocked % below threshold.");
                    $failed = true;
                }
                $protectedAttackPcts[] = $attacks['blocked_pct'];
            }
        }

        if ($directAttack['blocked_pct'] > $options['max-direct-attack-block-pct']) {
            err('FAIL: direct attack blocked % above threshold (baseline unexpectedly high).');
            $failed = true;
        }

        if (count($protectedAttackPcts) === 3) {
            $gap = max($protectedAttackPcts) - min($protectedAttackPcts);
            out(sprintf('Protected parity gap: %.2f%%', $gap));
            if ($gap > $options['max-protected-parity-gap-pct']) {
                err('FAIL: protected parity gap above threshold.');
                $failed = true;
            }
        }

        if ($failed) {
            err('Comprehensive verification FAILED.');
            return 1;
        }

        out('Comprehensive verification PASSED.');
        return 0;
    } finally {
        if (!$options['keep-up'] && !$options['skip-docker']) {
            out('==> Cleanup: docker compose down');
            runCmd(['docker', 'compose', '-f', $composeFile, 'down', '--remove-orphans'], $root);
        }
    }
}

exit(main($argv));
