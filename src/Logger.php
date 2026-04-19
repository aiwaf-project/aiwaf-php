<?php
namespace AIWAF;

class Logger
{
    private static ?string $override = null;          // ← setter wins
    public  const ENV   = 'AIWAF_FEATURE_LOG';        // ← env var key
    public  const FALLBACK = __DIR__ . '/../resources/request_features.csv';

    /** Call once (e.g. in bootstrap) if you need a custom path */
    public static function setLogFile(string $path): void
    {
        self::$override = $path;
    }

    /** Where should we log right now? */
    private static function path(): string
    {
        if (self::$override) {
            return self::$override;
        }

        // env-var?  e.g. export AIWAF_FEATURE_LOG=/var/log/aiwaf.csv
        $env = getenv(self::ENV);
        if ($env && $env !== '') {
            return $env;
        }

        // project-wide default (can live in Config.php)
        return defined('\\AIWAF\\Config::FEATURE_LOG')
            ? Config::FEATURE_LOG
            : self::FALLBACK;
    }

    /** Append one feature vector */
    public static function log(array $vector): void
    {
        $path = self::path();
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        $fh = fopen($path, 'a');
        if ($fh === false) {
            throw new \RuntimeException('Unable to open log file: ' . $path);
        }

        // Pass explicit escape char to avoid PHP 8.4 fputcsv deprecation warnings.
        fputcsv($fh, $vector, ',', '"', '\\');
        fclose($fh);
    }

    /** Build and append features from current request globals. */
    public static function logRequest(): void
    {
        $path = Utils::getRequestPath();
        $status = isset($_SERVER['REDIRECT_STATUS']) ? (string) $_SERVER['REDIRECT_STATUS'] : '200';

        $vector = [
            strlen($path),
            DynamicKeywordManager::detect($path),
            0.5,
            in_array((int) $status, [404, 500], true) ? 1 : 0,
            0,
            0,
            isset($_POST['aiwaf_honeytrap']) ? 1 : 0,
            UUIDTamperProtector::isSuspicious($path) ? 1 : 0,
        ];

        self::log($vector);
    }

    /** Load all rows */
    public static function readAll(): array
    {
        $file = self::path();
        if (!file_exists($file)) {
            return [];
        }

        $lines = file($file, FILE_IGNORE_NEW_LINES);
        if (!is_array($lines)) {
            return [];
        }

        $rows = [];
        foreach ($lines as $line) {
            $row = str_getcsv((string) $line, ',', '"', '\\');
            if (!is_array($row)) {
                continue;
            }
            $rows[] = array_map('floatval', $row);
        }

        return $rows;
    }
}
