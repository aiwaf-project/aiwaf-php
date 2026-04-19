<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class GeoIP
{
    /**
     * Best-effort country-code lookup using MaxMind DB reader if available.
     */
    public static function lookupCountry(string $ip, ?string $dbPath = null): ?string
    {
        $resolvedDbPath = self::resolveDbPath($dbPath);
        if ($resolvedDbPath === null) {
            return null;
        }

        if (!class_exists('MaxMind\\Db\\Reader')) {
            return null;
        }

        try {
            $readerClass = 'MaxMind\\Db\\Reader';
            $reader = new $readerClass($resolvedDbPath);
            $raw = $reader->get($ip);
            $reader->close();

            if (!is_array($raw)) {
                return null;
            }

            $code = self::extractCountryCode($raw);
            return $code !== '' ? strtoupper($code) : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Resolve an explicit database path or default to bundled geolock DB.
     */
    private static function resolveDbPath(?string $dbPath): ?string
    {
        if (is_string($dbPath) && $dbPath !== '' && file_exists($dbPath)) {
            return $dbPath;
        }

        $defaultPath = dirname(__DIR__) . '/geolock/ipinfo_lite.mmdb';
        if (file_exists($defaultPath)) {
            return $defaultPath;
        }

        return null;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function extractCountryCode(array $raw): string
    {
        foreach (['country_code', 'country_code2', 'country_code3'] as $key) {
            if (isset($raw[$key]) && is_string($raw[$key]) && $raw[$key] !== '') {
                return $raw[$key];
            }
        }

        if (isset($raw['country']) && is_array($raw['country'])) {
            $country = $raw['country'];
            if (isset($country['iso_code']) && is_string($country['iso_code'])) {
                return $country['iso_code'];
            }
        }

        if (isset($raw['country']) && is_string($raw['country'])) {
            return $raw['country'];
        }

        return '';
    }
}
