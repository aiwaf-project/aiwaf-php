<?php

declare(strict_types=1);

function out(string $text): void
{
    fwrite(STDOUT, $text . PHP_EOL);
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
        'repeat-adapter-matrix' => 1,
        'skip-cover-everything' => false,
        'skip-adapter-matrix' => false,
    ];

    foreach ($argv as $arg) {
        if ($arg === '--skip-cover-everything') {
            $options['skip-cover-everything'] = true;
            continue;
        }
        if ($arg === '--skip-adapter-matrix') {
            $options['skip-adapter-matrix'] = true;
            continue;
        }
        if (str_starts_with($arg, '--repeat-adapter-matrix=')) {
            $times = (int) substr($arg, strlen('--repeat-adapter-matrix='));
            $options['repeat-adapter-matrix'] = max(1, $times);
            continue;
        }
    }

    return $options;
}

function main(array $argv): int
{
    $root = dirname(__DIR__);
    $php = PHP_BINARY;
    $options = parseArgs(array_slice($argv, 1));

    if (!$options['skip-cover-everything']) {
        out('==> Validate: cover-everything');
        $cover = runCmd([$php, 'tools/cover-everything.php'], $root);
        if ($cover !== 0) {
            return $cover;
        }
    }

    if (!$options['skip-adapter-matrix']) {
        $repeat = (int) $options['repeat-adapter-matrix'];
        for ($i = 1; $i <= $repeat; $i++) {
            out(sprintf('==> Validate: adapter matrix run %d/%d', $i, $repeat));
            $matrix = runCmd([$php, 'tools/test-adapters-matrix.php', '--retries=2'], $root);
            if ($matrix !== 0) {
                return $matrix;
            }
        }
    }

    out('All validations PASSED.');
    return 0;
}

exit(main($argv));
