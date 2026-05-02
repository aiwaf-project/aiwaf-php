<?php
namespace AIWAF;

use AIWAF\Core\RuntimeConfig;
use AIWAF\Core\Defaults;

class Config
{
    public static $exemptPaths = Defaults::EXEMPT_PATHS;
    public static $knownPaths = [];
    public static $rateLimitPerMinute = 60;
    public static $keywordDetectionThreshold = 5;
    public static $uuidTamperThreshold = 3;
    public static $aiAnomalyThreshold = 0.65;
    public const FEATURE_LOG = __DIR__ . '/../resources/request_features.csv';

    public const BLOCKED_IPS_PATH = __DIR__ . '/../resources/blocked_ips.json';
    public const DYNAMIC_KEYWORDS_PATH = __DIR__ . '/../resources/dynamic_keywords.json';
    public const HEADER_MIN_SCORE = 3;
    public const REQUIRED_HEADERS = ['HTTP_USER_AGENT', 'HTTP_ACCEPT'];

    public static function toRuntimeConfig(): RuntimeConfig
    {
        return new RuntimeConfig(
            [
                'exempt_paths' => self::$exemptPaths,
                'known_paths' => self::$knownPaths,
                'rate_limit_per_minute' => self::$rateLimitPerMinute,
                'keyword_detection_threshold' => self::$keywordDetectionThreshold,
                'uuid_tamper_threshold' => self::$uuidTamperThreshold,
                'ai_anomaly_threshold' => self::$aiAnomalyThreshold,
                'blocked_ips_path' => self::BLOCKED_IPS_PATH,
                'keyword_store_path' => self::DYNAMIC_KEYWORDS_PATH,
                'header_min_score' => self::HEADER_MIN_SCORE,
                'required_headers' => self::REQUIRED_HEADERS,
            ],
            null,
            true
        );
    }
}
