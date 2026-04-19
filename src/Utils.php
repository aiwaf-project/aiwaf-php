<?php
namespace AIWAF;

use AIWAF\Core\Exemptions;
use AIWAF\Core\RuntimeUtils;

class Utils
{
    public static function loadJson(string $path): array
    {
        if (!file_exists($path)) {
            return [];
        }
        $json = file_get_contents($path);
        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }

    public static function saveJson(string $path, array $data): bool
    {
        $json = json_encode($data, JSON_PRETTY_PRINT);
        return file_put_contents($path, $json) !== false;
    }

    public static function log(string $message): void
    {
        error_log('[AIWAF] ' . $message);
    }

    public static function isExemptPath(string $path, array $exemptPaths): bool
    {
        return Exemptions::isPathExempt($path, $exemptPaths, true, true);
    }

    public static function getClientIp(): string
    {
        return RuntimeUtils::getIpFromHeaders($_SERVER);
    }

    public static function saveBlockedIps(array $blockedIps): void
    {
        $projectRoot = dirname(__DIR__);
        $resourcesPath = $projectRoot . '/resources';
        $blockedIpsFile = $resourcesPath . '/blocked_ips.json';

        if (!file_exists($resourcesPath)) {
            mkdir($resourcesPath, 0777, true);
        }
        if (!file_exists($blockedIpsFile)) {
            file_put_contents($blockedIpsFile, json_encode([], JSON_PRETTY_PRINT));
        }
        file_put_contents($blockedIpsFile, json_encode($blockedIps, JSON_PRETTY_PRINT));
    }

    public static function getRequestPath(): string
    {
        return RuntimeUtils::getRequestPath($_SERVER);
    }
}
