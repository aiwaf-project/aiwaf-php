<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class StorageOps
{
    /**
     * @param array<string, array<int, string>> $schemaHeaders
     */
    public static function ensureCsvFiles(string $dataDir, array $schemaHeaders): void
    {
        self::safeCsvOperation(function () use ($dataDir, $schemaHeaders): void {
            if (!is_dir($dataDir)) {
                mkdir($dataDir, 0777, true);
            }

            foreach ($schemaHeaders as $name => $headers) {
                $filePath = rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name;
                if (file_exists($filePath)) {
                    continue;
                }

                self::withFileLock($filePath, 'w', function ($fh) use ($headers): void {
                    fputcsv($fh, $headers, ',', '"', '\\');
                });
            }
        });
    }

    /**
     * @param array<string, array<int, string>> $schemaHeaders
     * @return array<int, string>
     */
    public static function readCsvSet(string $dataDir, string $filename, string $keyField, array $schemaHeaders): array
    {
        return self::safeCsvOperation(function () use ($dataDir, $filename, $keyField, $schemaHeaders): array {
            self::ensureCsvFiles($dataDir, $schemaHeaders);

            $filePath = rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;
            $items = [];

            self::withFileLock($filePath, 'r', function ($fh) use (&$items, $keyField): void {
                $header = fgetcsv($fh, 0, ',', '"', '\\');
                if (!is_array($header)) {
                    return;
                }

                $keyIndex = array_search($keyField, $header, true);
                if ($keyIndex === false) {
                    return;
                }

                while (($row = fgetcsv($fh, 0, ',', '"', '\\')) !== false) {
                    $value = isset($row[$keyIndex]) ? trim((string) $row[$keyIndex]) : '';
                    if ($value !== '') {
                        $items[$value] = true;
                    }
                }
            });

            return array_keys($items);
        });
    }

    /**
     * @param array<string, array<int, string>> $schemaHeaders
     * @return array<string, string>
     */
    public static function readCsvDict(string $dataDir, string $filename, string $keyField, string $valueField, array $schemaHeaders): array
    {
        return self::safeCsvOperation(function () use ($dataDir, $filename, $keyField, $valueField, $schemaHeaders): array {
            self::ensureCsvFiles($dataDir, $schemaHeaders);

            $filePath = rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;
            $items = [];

            self::withFileLock($filePath, 'r', function ($fh) use (&$items, $keyField, $valueField): void {
                $header = fgetcsv($fh, 0, ',', '"', '\\');
                if (!is_array($header)) {
                    return;
                }

                $keyIndex = array_search($keyField, $header, true);
                $valueIndex = array_search($valueField, $header, true);
                if ($keyIndex === false || $valueIndex === false) {
                    return;
                }

                while (($row = fgetcsv($fh, 0, ',', '"', '\\')) !== false) {
                    $key = isset($row[$keyIndex]) ? trim((string) $row[$keyIndex]) : '';
                    if ($key === '') {
                        continue;
                    }
                    $items[$key] = isset($row[$valueIndex]) ? (string) $row[$valueIndex] : '';
                }
            });

            return $items;
        });
    }

    /**
     * @param array<int, string> $row
     * @param array<string, array<int, string>> $schemaHeaders
     */
    public static function appendCsvRow(string $dataDir, string $filename, array $row, array $schemaHeaders): void
    {
        self::safeCsvOperation(function () use ($dataDir, $filename, $row, $schemaHeaders): void {
            self::ensureCsvFiles($dataDir, $schemaHeaders);
            $filePath = rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;

            self::withFileLock($filePath, 'a', function ($fh) use ($row): void {
                fputcsv($fh, $row, ',', '"', '\\');
            });
        });
    }

    /**
     * @param array<int, array<int, string>> $rows
     * @param array<string, array<int, string>> $schemaHeaders
     */
    public static function rewriteCsvRows(string $dataDir, string $filename, array $rows, array $schemaHeaders): void
    {
        self::safeCsvOperation(function () use ($dataDir, $filename, $rows, $schemaHeaders): void {
            self::ensureCsvFiles($dataDir, $schemaHeaders);
            $filePath = rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;

            self::withFileLock($filePath, 'w', function ($fh) use ($rows, $filename, $schemaHeaders): void {
                fputcsv($fh, $schemaHeaders[$filename], ',', '"', '\\');
                foreach ($rows as $row) {
                    fputcsv($fh, $row, ',', '"', '\\');
                }
            });
        });
    }

    public static function nowIso(): string
    {
        return date(DATE_ATOM);
    }

    /**
     * @template T
     * @param callable():T $operation
     * @return T
     */
    private static function safeCsvOperation(callable $operation, int $maxRetries = 5, float $baseDelay = 0.01)
    {
        $lastException = null;

        for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
            try {
                return $operation();
            } catch (\Throwable $e) {
                $lastException = $e;
                if ($attempt < $maxRetries - 1) {
                    $delay = $baseDelay * (2 ** $attempt) + (mt_rand(0, 10) / 1000.0);
                    usleep((int) ($delay * 1000000));
                    continue;
                }
            }
        }

        throw $lastException ?? new \RuntimeException('CSV operation failed');
    }

    /**
     * @param callable(resource):void $callback
     */
    private static function withFileLock(string $filePath, string $mode, callable $callback): void
    {
        $fh = fopen($filePath, $mode);
        if ($fh === false) {
            throw new \RuntimeException('Unable to open file: ' . $filePath);
        }

        $lockType = ($mode === 'r') ? LOCK_SH : LOCK_EX;
        try {
            if (!flock($fh, $lockType)) {
                throw new \RuntimeException('Unable to lock file: ' . $filePath);
            }
            $callback($fh);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
}
