<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class StorageCsvImpl
{
    public static function ensureAll(string $dataDir): void
    {
        StorageOps::ensureCsvFiles($dataDir, StorageSchema::CSV_HEADERS);
    }

    /** @return array<int, string> */
    public static function readWhitelist(string $dataDir): array
    {
        return StorageOps::readCsvSet($dataDir, StorageSchema::WHITELIST_CSV, 'ip', StorageSchema::CSV_HEADERS);
    }

    public static function appendWhitelist(string $dataDir, string $ip): void
    {
        StorageOps::appendCsvRow($dataDir, StorageSchema::WHITELIST_CSV, [$ip, StorageOps::nowIso()], StorageSchema::CSV_HEADERS);
    }

    /** @param array<int, string> $whitelist */
    public static function rewriteWhitelist(string $dataDir, array $whitelist): void
    {
        $rows = [];
        foreach ($whitelist as $ip) {
            $rows[] = [(string) $ip, StorageOps::nowIso()];
        }
        StorageOps::rewriteCsvRows($dataDir, StorageSchema::WHITELIST_CSV, $rows, StorageSchema::CSV_HEADERS);
    }

    /** @return array<string, string> */
    public static function readBlacklist(string $dataDir): array
    {
        return StorageOps::readCsvDict($dataDir, StorageSchema::BLACKLIST_CSV, 'ip', 'reason', StorageSchema::CSV_HEADERS);
    }

    public static function appendBlacklist(string $dataDir, string $ip, string $reason, string $infoJson = ''): void
    {
        StorageOps::appendCsvRow(
            $dataDir,
            StorageSchema::BLACKLIST_CSV,
            [$ip, $reason, StorageOps::nowIso(), $infoJson],
            StorageSchema::CSV_HEADERS
        );
    }

    /** @return array<int, string> */
    public static function readKeywords(string $dataDir): array
    {
        return StorageOps::readCsvSet($dataDir, StorageSchema::KEYWORDS_CSV, 'keyword', StorageSchema::CSV_HEADERS);
    }

    public static function appendKeyword(string $dataDir, string $keyword): void
    {
        StorageOps::appendCsvRow($dataDir, StorageSchema::KEYWORDS_CSV, [$keyword, StorageOps::nowIso()], StorageSchema::CSV_HEADERS);
    }

    /** @return array<int, string> */
    public static function readGeoBlockedCountries(string $dataDir): array
    {
        $countries = StorageOps::readCsvSet($dataDir, StorageSchema::GEO_BLOCKED_COUNTRIES_CSV, 'country', StorageSchema::CSV_HEADERS);
        return array_values(array_unique(array_map('strtoupper', $countries)));
    }

    public static function appendGeoBlockedCountry(string $dataDir, string $countryCode): void
    {
        StorageOps::appendCsvRow(
            $dataDir,
            StorageSchema::GEO_BLOCKED_COUNTRIES_CSV,
            [strtoupper($countryCode), StorageOps::nowIso()],
            StorageSchema::CSV_HEADERS
        );
    }

    /** @return array<string, string> */
    public static function readPathExemptions(string $dataDir): array
    {
        return StorageOps::readCsvDict($dataDir, StorageSchema::PATH_EXEMPTIONS_CSV, 'path', 'reason', StorageSchema::CSV_HEADERS);
    }

    public static function appendPathExemption(string $dataDir, string $path, string $reason): void
    {
        StorageOps::appendCsvRow(
            $dataDir,
            StorageSchema::PATH_EXEMPTIONS_CSV,
            [$path, $reason, StorageOps::nowIso()],
            StorageSchema::CSV_HEADERS
        );
    }
}
