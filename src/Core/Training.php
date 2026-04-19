<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class Training
{
    /**
     * @return array<int, array<mixed>>
     */
    public static function iterBatches(array $items, int $batchSize): array
    {
        $batchSize = max(1, $batchSize);
        return array_chunk($items, $batchSize);
    }

    /**
     * Mirrors Python's extract_rust_features_parallel behavior:
     * - Empty input => []
     * - Single worker or small dataset => single extractor call
     * - Chunked extraction otherwise
     * - If any chunk result is null, return null
     *
     * @param array<int, mixed> $records
     * @param array<int, string> $staticKeywords
     * @param callable $extractFn fn(array $recordsChunk, array $staticKeywords): ?array
     * @return array<int, mixed>|null
     */
    public static function extractRustFeaturesParallel(
        array $records,
        array $staticKeywords,
        int $chunkSize,
        int $maxWorkers,
        callable $extractFn
    ): ?array {
        if ($records === []) {
            return [];
        }

        $chunkSize = max(1, $chunkSize);
        $maxWorkers = max(1, $maxWorkers);

        if ($maxWorkers === 1 || count($records) <= $chunkSize) {
            $result = $extractFn($records, $staticKeywords);
            return $result === null ? null : array_values($result);
        }

        $chunks = array_chunk($records, $chunkSize);

        if (function_exists('pcntl_fork') && function_exists('pcntl_wait')) {
            $parallel = self::extractWithForks($chunks, $staticKeywords, $maxWorkers, $extractFn);
            if ($parallel !== null) {
                return $parallel;
            }
        }

        $features = [];
        foreach ($chunks as $chunk) {
            $result = $extractFn($chunk, $staticKeywords);
            if ($result === null) {
                return null;
            }
            foreach ($result as $row) {
                $features[] = $row;
            }
        }

        return $features;
    }

    /**
     * Best-effort process parallelism (POSIX). Returns null on any failure so caller can safely fall back.
     *
     * @param array<int, array<int, mixed>> $chunks
     * @param array<int, string> $staticKeywords
     * @param callable $extractFn
     * @return array<int, mixed>|null
     */
    private static function extractWithForks(array $chunks, array $staticKeywords, int $maxWorkers, callable $extractFn): ?array
    {
        $active = [];
        $next = 0;
        $total = count($chunks);
        $resultsByIndex = [];

        while ($next < $total || $active !== []) {
            while ($next < $total && count($active) < $maxWorkers) {
                $idx = $next;
                $tmp = tempnam(sys_get_temp_dir(), 'aiwaf_chunk_');
                if ($tmp === false) {
                    return null;
                }

                $pid = pcntl_fork();
                if ($pid === -1) {
                    @unlink($tmp);
                    return null;
                }

                if ($pid === 0) {
                    try {
                        $chunkResult = $extractFn($chunks[$idx], $staticKeywords);
                        $payload = [
                            'ok' => $chunkResult !== null,
                            'result' => $chunkResult,
                        ];
                    } catch (\Throwable $e) {
                        $payload = ['ok' => false, 'result' => null];
                    }

                    @file_put_contents($tmp, json_encode($payload));
                    exit(0);
                }

                $active[$pid] = ['idx' => $idx, 'tmp' => $tmp];
                $next++;
            }

            $endedPid = pcntl_wait($status);
            if ($endedPid <= 0 || !isset($active[$endedPid])) {
                continue;
            }

            $meta = $active[$endedPid];
            unset($active[$endedPid]);

            $raw = @file_get_contents($meta['tmp']);
            @unlink($meta['tmp']);
            if ($raw === false || $raw === '') {
                return null;
            }

            $decoded = json_decode($raw, true);
            if (!is_array($decoded) || !($decoded['ok'] ?? false) || !is_array($decoded['result'])) {
                return null;
            }

            $resultsByIndex[$meta['idx']] = $decoded['result'];
        }

        ksort($resultsByIndex);
        $features = [];
        foreach ($resultsByIndex as $chunkRows) {
            foreach ($chunkRows as $row) {
                $features[] = $row;
            }
        }

        return $features;
    }
}
