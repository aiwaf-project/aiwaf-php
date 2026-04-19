<?php
namespace AIWAF;

use AIWAF\Core\BlacklistManager;

class IPBlocker
{
    public static function blockIp(string $ip, string $reason = 'Runtime block', ?int $duration = null): void
    {
        BlacklistManager::block($ip, Config::BLOCKED_IPS_PATH, $reason, $duration);
        Utils::log("Blocking IP: $ip");
    }

    public static function blockTemporaryIp(string $ip, string $reason = 'Temporary block', int $durationSeconds = 3600): void
    {
        self::blockIp($ip, $reason, max(1, $durationSeconds));
    }

    public static function blockPermanentIp(string $ip, string $reason = 'Permanent block'): void
    {
        self::blockIp($ip, $reason, null);
    }

    public static function getBlockedIps(): array
    {
        return BlacklistManager::all(Config::BLOCKED_IPS_PATH);
    }

    public static function isBlocked(string $ip): bool
    {
        return BlacklistManager::isBlocked($ip, Config::BLOCKED_IPS_PATH);
    }

    public static function unblockIp(string $ip): void
    {
        BlacklistManager::unblock($ip, Config::BLOCKED_IPS_PATH);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public static function getBlockedEntries(): array
    {
        return BlacklistManager::allEntries(Config::BLOCKED_IPS_PATH);
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function getBlockedInfo(string $ip): ?array
    {
        return BlacklistManager::getEntry($ip, Config::BLOCKED_IPS_PATH);
    }
}
