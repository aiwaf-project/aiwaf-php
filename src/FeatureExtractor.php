<?php
namespace AIWAF;

use AIWAF\Core\Constants;
use AIWAF\Core\Training;

class FeatureExtractor
{
    /**
     * Build normalized record rows used by training.
     *
     * @param array<int, array<string, mixed>> $parsed
     * @param array<string, int> $ip404
     * @param callable|null $pathExistsFn fn(string $path): bool
     * @param callable|null $pathExemptFn fn(string $path): bool
     * @param array<int, string> $statusIdxList
     * @return array<int, array<string, mixed>>
     */
    public static function buildRecords(
        array $parsed,
        array $ip404,
        ?callable $pathExistsFn,
        ?callable $pathExemptFn,
        array $statusIdxList = Constants::STATUS_IDX
    ): array {
        $records = [];
        $knownCache = [];
        $exemptCache = [];

        foreach ($parsed as $record) {
            $path = (string) ($record['path'] ?? '');

            if (!array_key_exists($path, $knownCache)) {
                try {
                    $knownCache[$path] = $pathExistsFn ? (bool) $pathExistsFn($path) : false;
                } catch (\Throwable $e) {
                    $knownCache[$path] = false;
                }
            }

            if (!array_key_exists($path, $exemptCache)) {
                try {
                    $exemptCache[$path] = $pathExemptFn ? (bool) $pathExemptFn($path) : false;
                } catch (\Throwable $e) {
                    $exemptCache[$path] = false;
                }
            }

            $status = (string) ($record['status'] ?? '');
            $statusIdx = array_search($status, $statusIdxList, true);
            if ($statusIdx === false) {
                $statusIdx = -1;
            }

            $timestamp = $record['timestamp'] ?? microtime(true);
            if ($timestamp instanceof \DateTimeInterface) {
                $epoch = (float) $timestamp->format('U.u');
            } else {
                $epoch = (float) $timestamp;
            }

            $records[] = [
                'ip' => (string) ($record['ip'] ?? ''),
                'path_len' => strlen($path),
                'path_lower' => strtolower($path),
                'resp_time' => (float) ($record['response_time'] ?? 0),
                'status_idx' => $statusIdx,
                'timestamp' => $timestamp,
                'timestamp_epoch' => $epoch,
                'kw_check' => !$knownCache[$path] && !$exemptCache[$path],
                'total_404' => (int) ($ip404[(string) ($record['ip'] ?? '')] ?? 0),
            ];
        }

        return $records;
    }

    /**
     * @param array<int, array<string, mixed>> $records
     * @return array<int, array<string, mixed>>
     */
    public static function rustPayloadFromRecords(array $records): array
    {
        $payload = [];
        foreach ($records as $rec) {
            $payload[] = [
                'ip' => (string) ($rec['ip'] ?? ''),
                'path_lower' => (string) ($rec['path_lower'] ?? ''),
                'path_len' => (int) ($rec['path_len'] ?? 0),
                'timestamp' => (float) ($rec['timestamp_epoch'] ?? 0),
                'response_time' => (float) ($rec['resp_time'] ?? 0),
                'status_idx' => (int) ($rec['status_idx'] ?? -1),
                'kw_check' => (bool) ($rec['kw_check'] ?? false),
                'total_404' => (int) ($rec['total_404'] ?? 0),
            ];
        }
        return $payload;
    }

    /**
     * @param array<string, mixed> $record
     * @param array<string, array<int, float|int>> $ipTimes
     * @param array<int, string> $staticKw
     * @return array<string, mixed>
     */
    public static function pythonFeatureFromRecord(array $record, array $ipTimes, array $staticKw): array
    {
        $kwHits = 0;
        $pathLower = (string) ($record['path_lower'] ?? '');
        if ((bool) ($record['kw_check'] ?? false)) {
            foreach ($staticKw as $kw) {
                if ($kw !== '' && strpos($pathLower, strtolower((string) $kw)) !== false) {
                    $kwHits++;
                }
            }
        }

        $burst = 0;
        $recordTs = self::toEpochSeconds($record['timestamp'] ?? microtime(true));
        $timestamps = $ipTimes[(string) ($record['ip'] ?? '')] ?? [];
        foreach ($timestamps as $ts) {
            if (($recordTs - (float) $ts) <= 10) {
                $burst++;
            }
        }

        return [
            'ip' => (string) ($record['ip'] ?? ''),
            'path_len' => (int) ($record['path_len'] ?? 0),
            'kw_hits' => $kwHits,
            'resp_time' => (float) ($record['resp_time'] ?? 0),
            'status_idx' => (int) ($record['status_idx'] ?? -1),
            'burst_count' => $burst,
            'total_404' => (int) ($record['total_404'] ?? 0),
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $records
     * @param array<string, array<int, float|int>> $ipTimes
     * @param array<int, string> $staticKw
     * @return array<int, array<string, mixed>>
     */
    public static function pythonFeaturesBatched(
        array $records,
        array $ipTimes,
        array $staticKw,
        int $batchSize,
        bool $parallelEnabled,
        int $parallelChunkSize,
        int $maxWorkers
    ): array {
        if ($records === []) {
            return [];
        }

        $batchSize = max(1, $batchSize);
        $parallelChunkSize = max(1, $parallelChunkSize);
        $maxWorkers = max(1, $maxWorkers);

        $features = [];
        $batches = Training::iterBatches($records, $batchSize);

        if ($parallelEnabled && $maxWorkers > 1) {
            foreach ($batches as $batch) {
                if (count($batch) >= $parallelChunkSize) {
                    foreach ($batch as $rec) {
                        $features[] = self::pythonFeatureFromRecord($rec, $ipTimes, $staticKw);
                    }
                    continue;
                }

                foreach ($batch as $rec) {
                    $features[] = self::pythonFeatureFromRecord($rec, $ipTimes, $staticKw);
                }
            }

            return $features;
        }

        foreach ($batches as $batch) {
            foreach ($batch as $rec) {
                $features[] = self::pythonFeatureFromRecord($rec, $ipTimes, $staticKw);
            }
        }

        return $features;
    }

    public static function extractFeatures(array $request): array
    {
        $status = (string) ($request['status'] ?? 200);
        $statusIdx = array_search($status, Constants::STATUS_IDX, true);
        if ($statusIdx === false) {
            $statusIdx = -1;
        }

        $path = (string) ($request['path'] ?? '');
        $record = [
            'ip' => (string) ($request['ip'] ?? ''),
            'path_len' => strlen($path),
            'path_lower' => strtolower($path),
            'resp_time' => (float) ($request['resp_time'] ?? 0),
            'status_idx' => $statusIdx,
            'timestamp' => $request['timestamp'] ?? microtime(true),
            'kw_check' => (bool) ($request['kw_check'] ?? true),
            'total_404' => (int) ($request['total_404'] ?? 0),
        ];

        $staticKw = isset($request['static_kw']) && is_array($request['static_kw'])
            ? array_values($request['static_kw'])
            : ['admin', 'config', 'wp-', '.env'];
        $ipTimes = isset($request['ip_times']) && is_array($request['ip_times']) ? $request['ip_times'] : [];

        return self::pythonFeatureFromRecord($record, $ipTimes, $staticKw);
    }

    /**
     * @param mixed $timestamp
     */
    private static function toEpochSeconds($timestamp): float
    {
        if ($timestamp instanceof \DateTimeInterface) {
            return (float) $timestamp->format('U.u');
        }

        return (float) $timestamp;
    }
}
