<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class Logs
{
    /**
     * @return array<int, string>
     */
    public static function readRotatedLogs(string $basePath): array
    {
        $lines = [];

        self::appendPathLines($basePath, $lines);

        $rotated = glob($basePath . '.*');
        if (!is_array($rotated)) {
            $rotated = [];
        }
        sort($rotated);

        foreach ($rotated as $path) {
            if (!is_string($path)) {
                continue;
            }

            self::appendPathLines($path, $lines);
        }

        return $lines;
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function parseLogLine(string $line): ?array
    {
        $patterns = [
            // Combined log format with response-time, IPv4/IPv6.
            '/^([0-9A-Fa-f:.]+)\s+.*\[(.*?)\].*"[A-Z]+\s+(.*?)\s+HTTP\/.*?"\s+(\d{3}).*?response-time=([0-9]*\.?[0-9]+)/',
            // Standard combined log format, IPv4/IPv6.
            '/^([0-9A-Fa-f:.]+)\s+.*\[(.*?)\].*"[A-Z]+\s+(.*?)\s+HTTP\/.*?"\s+(\d{3})\s+(\d+)\s+".*?"\s+".*?"/',
            // Common log format, IPv4/IPv6.
            '/^([0-9A-Fa-f:.]+)\s+.*\[(.*?)\].*"[A-Z]+\s+(.*?)\s+HTTP\/.*?"\s+(\d{3})\s+(\d+)/',
        ];

        foreach ($patterns as $pattern) {
            $matches = [];
            if (@preg_match($pattern, $line, $matches) !== 1) {
                continue;
            }

            $ip = (string) ($matches[1] ?? '');
            $timestampRaw = (string) ($matches[2] ?? '');
            $path = (string) ($matches[3] ?? '');
            $status = (string) ($matches[4] ?? '');

            $responseTime = 0.0;
            for ($idx = 5; $idx < count($matches); $idx++) {
                $candidate = (string) $matches[$idx];
                if (strpos($candidate, '.') !== false && is_numeric($candidate)) {
                    $responseTime = (float) $candidate;
                    break;
                }
            }

            if (isset($matches[5]) && is_numeric((string) $matches[5]) && $responseTime === 0.0 && strpos((string) $matches[5], '.') !== false) {
                $responseTime = (float) $matches[5];
            }

            $timestampMain = trim(explode(' ', $timestampRaw)[0]);
            $date = \DateTime::createFromFormat('d/M/Y:H:i:s', $timestampMain);
            if (!$date instanceof \DateTime) {
                try {
                    $date = new \DateTime(str_replace('Z', '+00:00', $timestampRaw));
                } catch (\Throwable $e) {
                    continue;
                }
            }

            return [
                'ip' => $ip,
                'timestamp' => $date,
                'path' => $path,
                'status' => $status,
                'response_time' => $responseTime,
            ];
        }

        return null;
    }

    /**
     * @param array<int, string> $lines
     */
    private static function appendPathLines(string $path, array &$lines): void
    {
        if (!is_file($path)) {
            return;
        }

        if (self::isCsvPath($path)) {
            foreach (self::readCsvAsAccessLines($path) as $line) {
                $lines[] = $line;
            }
            return;
        }

        if (substr($path, -3) === '.gz') {
            $handle = @gzopen($path, 'rb');
            if ($handle === false) {
                return;
            }
            while (!gzeof($handle)) {
                $line = gzgets($handle);
                if ($line === false) {
                    break;
                }
                $lines[] = rtrim($line, "\r\n");
            }
            @gzclose($handle);
            return;
        }

        $content = @file($path, FILE_IGNORE_NEW_LINES);
        if (is_array($content)) {
            foreach ($content as $line) {
                $lines[] = (string) $line;
            }
        }
    }

    private static function isCsvPath(string $path): bool
    {
        return (bool) preg_match('/\.csv(?:\.gz)?$/i', $path);
    }

    /**
     * @return array<int, string>
     */
    private static function readCsvAsAccessLines(string $path): array
    {
        $lines = [];

        if (substr($path, -3) === '.gz') {
            $handle = @gzopen($path, 'rb');
            if ($handle === false) {
                return [];
            }

            $temp = fopen('php://temp', 'w+');
            if ($temp === false) {
                @gzclose($handle);
                return [];
            }

            while (!gzeof($handle)) {
                $chunk = gzread($handle, 8192);
                if ($chunk === false) {
                    break;
                }
                fwrite($temp, $chunk);
            }
            @gzclose($handle);

            rewind($temp);
            $lines = self::readCsvStreamAsAccessLines($temp);
            fclose($temp);
            return $lines;
        }

        $fh = @fopen($path, 'r');
        if ($fh === false) {
            return [];
        }

        $lines = self::readCsvStreamAsAccessLines($fh);
        fclose($fh);
        return $lines;
    }

    /**
     * @param resource $fh
     * @return array<int, string>
     */
    private static function readCsvStreamAsAccessLines($fh): array
    {
        $lines = [];

        $header = fgetcsv($fh, 0, ',', '"', '\\');
        if (!is_array($header)) {
            return [];
        }

        $index = [];
        foreach ($header as $idx => $name) {
            $index[strtolower(trim((string) $name))] = $idx;
        }

        while (($row = fgetcsv($fh, 0, ',', '"', '\\')) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $timestamp = self::csvValue($row, $index, ['timestamp', 'time', 'created_at']);
            $ip = self::csvValue($row, $index, ['ip', 'ip_address', 'remote_addr']);
            $method = strtoupper(self::csvValue($row, $index, ['method', 'http_method'], 'GET'));
            $path = self::csvValue($row, $index, ['path', 'uri', 'request_uri'], '/');
            $status = self::csvValue($row, $index, ['status_code', 'status'], '200');
            $size = self::csvValue($row, $index, ['content_length', 'size', 'bytes'], '0');
            $referer = self::csvValue($row, $index, ['referer', 'referrer'], '-');
            $ua = self::csvValue($row, $index, ['user_agent', 'ua'], '-');
            $responseTime = self::csvValue($row, $index, ['response_time', 'resp_time', 'duration'], '0');

            if ($timestamp === '' || $ip === '') {
                continue;
            }

            $ts = self::formatTimestampForAccessLog($timestamp);
            $lines[] = sprintf(
                '%s - - [%s] "%s %s HTTP/1.1" %s %s "%s" "%s" response-time=%s',
                $ip,
                $ts,
                $method !== '' ? $method : 'GET',
                $path !== '' ? $path : '/',
                $status !== '' ? $status : '200',
                $size !== '' ? $size : '0',
                $referer !== '' ? $referer : '-',
                $ua !== '' ? $ua : '-',
                $responseTime !== '' ? $responseTime : '0'
            );
        }

        return $lines;
    }

    /**
     * @param array<int, string> $candidates
     * @param array<string, int> $index
     * @param array<int, string> $row
     */
    private static function csvValue(array $row, array $index, array $candidates, string $default = ''): string
    {
        foreach ($candidates as $candidate) {
            $key = strtolower($candidate);
            if (!isset($index[$key])) {
                continue;
            }

            $position = $index[$key];
            if (!isset($row[$position])) {
                continue;
            }

            return trim((string) $row[$position]);
        }

        return $default;
    }

    private static function formatTimestampForAccessLog(string $rawTimestamp): string
    {
        try {
            $dt = new \DateTime($rawTimestamp);
            return $dt->format('d/M/Y:H:i:s O');
        } catch (\Throwable $e) {
            return $rawTimestamp;
        }
    }
}
