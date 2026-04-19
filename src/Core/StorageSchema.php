<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class StorageSchema
{
    public const DEFAULT_DATA_DIR = 'aiwaf_data';

    public const WHITELIST_CSV = 'whitelist.csv';
    public const BLACKLIST_CSV = 'blacklist.csv';
    public const KEYWORDS_CSV = 'keywords.csv';
    public const GEO_BLOCKED_COUNTRIES_CSV = 'geo_blocked_countries.csv';
    public const PATH_EXEMPTIONS_CSV = 'path_exemptions.csv';

    public const CSV_HEADERS = [
        self::WHITELIST_CSV => ['ip', 'added_date'],
        self::BLACKLIST_CSV => ['ip', 'reason', 'added_date', 'extended_request_info'],
        self::KEYWORDS_CSV => ['keyword', 'added_date'],
        self::GEO_BLOCKED_COUNTRIES_CSV => ['country', 'added_date'],
        self::PATH_EXEMPTIONS_CSV => ['path', 'reason', 'added_date'],
    ];
}
