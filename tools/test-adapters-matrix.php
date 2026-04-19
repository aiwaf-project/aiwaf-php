<?php

declare(strict_types=1);

function out(string $text): void
{
    fwrite(STDOUT, $text . PHP_EOL);
}

function err(string $text): void
{
    fwrite(STDERR, $text . PHP_EOL);
}

function runCmd(array $cmd, ?string $cwd = null): int
{
    $parts = array_map(static fn(string $p): string => escapeshellarg($p), $cmd);
    $command = implode(' ', $parts);

    $proc = proc_open($command, [0 => STDIN, 1 => STDOUT, 2 => STDERR], $pipes, $cwd);
    if (!is_resource($proc)) {
        throw new RuntimeException('Failed to start command: ' . $command);
    }

    return proc_close($proc);
}

function parseArgs(array $argv): array
{
    $options = [
        'keep-up' => false,
        'no-build' => false,
        'retries' => 2,
    ];

    foreach ($argv as $arg) {
        if ($arg === '--keep-up') {
            $options['keep-up'] = true;
            continue;
        }

        if ($arg === '--no-build') {
            $options['no-build'] = true;
            continue;
        }

        if (str_starts_with($arg, '--retries=')) {
            $raw = (int) substr($arg, strlen('--retries='));
            $options['retries'] = max(1, $raw);
            continue;
        }
    }

    return $options;
}

function dumpDiagnostics(string $composeFile, string $root): void
{
    err('==> Adapter matrix diagnostics');
    runCmd(['docker', 'compose', '-f', $composeFile, 'ps'], $root);
    runCmd(['docker', 'compose', '-f', $composeFile, 'logs', '--no-color', '--tail', '200'], $root);
}

function main(array $argv): int
{
    $root = dirname(__DIR__);
    $composeFile = $root . DIRECTORY_SEPARATOR . 'examples' . DIRECTORY_SEPARATOR . 'sandbox' . DIRECTORY_SEPARATOR . 'docker-compose.adapters.yml';
    $options = parseArgs(array_slice($argv, 1));
    $keepUp = $options['keep-up'];
    $noBuild = $options['no-build'];
    $retries = $options['retries'];

    $lastExit = 1;

    for ($attempt = 1; $attempt <= $retries; $attempt++) {
        out(sprintf('==> Adapter matrix attempt %d/%d', $attempt, $retries));

        // Best-effort cleanup so repeated runs do not collide with stale containers.
        runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);

        $upCmd = ['docker', 'compose', '-f', $composeFile, 'up', '-d', '--remove-orphans'];
        if (!$noBuild) {
            $upCmd[] = '--build';
        }

        $up = runCmd($upCmd, $root);
        if ($up !== 0) {
            err('Failed to start adapter matrix stack.');
            dumpDiagnostics($composeFile, $root);
            $lastExit = 1;
            continue;
        }

        $testExit = runCmd(['docker', 'compose', '-f', $composeFile, 'run', '--rm', 'aiwaf-adapter-tests'], $root);

        if ($testExit === 0) {
            if (!$keepUp) {
                runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);
            }
            out('Adapter matrix PASSED.');
            return 0;
        }

        err('Adapter matrix tests failed on this attempt.');
        dumpDiagnostics($composeFile, $root);
        $lastExit = $testExit;
    }

    if (!$keepUp) {
        runCmd(['docker', 'compose', '-f', $composeFile, 'down', '-v', '--remove-orphans'], $root);
    }

    err('Adapter matrix FAILED after all retry attempts.');
    return $lastExit;
}

exit(main($argv));
