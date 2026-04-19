<?php
namespace AIWAF\Core;

final class BlacklistManager
{
    public static function block(string $ip, string $path, string $reason = 'Manual block', ?int $duration = null): void
    {
        $entries = self::readEntries($path);
        $now = microtime(true);

        $updated = false;
        foreach ($entries as &$entry) {
            if (($entry['ip'] ?? '') !== $ip) {
                continue;
            }

            $entry['reason'] = $reason;
            $entry['blocked_at'] = $now;
            $entry['duration'] = $duration;
            $entry['permanent'] = $duration === null;
            $updated = true;
            break;
        }
        unset($entry);

        if (!$updated) {
            $entries[] = [
                'ip' => $ip,
                'reason' => $reason,
                'blocked_at' => $now,
                'duration' => $duration,
                'permanent' => $duration === null,
            ];
        }

        self::writeEntries($path, $entries);
    }

    public static function unblock(string $ip, string $path): void
    {
        $entries = array_values(array_filter(self::readEntries($path), static function (array $entry) use ($ip): bool {
            return (string) ($entry['ip'] ?? '') !== $ip;
        }));
        self::writeEntries($path, $entries);
    }

    public static function isBlocked(string $ip, string $path): bool
    {
        $entries = self::readEntries($path);
        $changed = false;

        foreach ($entries as $entry) {
            if ((string) ($entry['ip'] ?? '') !== $ip) {
                continue;
            }

            if (!self::isEntryActive($entry, microtime(true))) {
                $changed = true;
                break;
            }

            return true;
        }

        if ($changed) {
            self::writeEntries($path, self::activeEntries($entries));
        }

        return false;
    }

    public static function all(string $path): array
    {
        $entries = self::readEntries($path);
        $active = self::activeEntries($entries);
        if (count($active) !== count($entries)) {
            self::writeEntries($path, $active);
        }

        return array_values(array_map(static function (array $entry): string {
            return (string) ($entry['ip'] ?? '');
        }, $active));
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public static function allEntries(string $path): array
    {
        $entries = self::readEntries($path);
        $active = self::activeEntries($entries);
        if (count($active) !== count($entries)) {
            self::writeEntries($path, $active);
        }

        return $active;
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function getEntry(string $ip, string $path): ?array
    {
        foreach (self::allEntries($path) as $entry) {
            if ((string) ($entry['ip'] ?? '') === $ip) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private static function readEntries(string $path): array
    {
        if (!file_exists($path)) {
            return [];
        }

        $json = file_get_contents($path);
        $decoded = json_decode((string) $json, true);

        if (!is_array($decoded)) {
            return [];
        }

        $entries = [];
        foreach ($decoded as $row) {
            if (is_string($row) && $row !== '') {
                $entries[] = [
                    'ip' => $row,
                    'reason' => 'Legacy block',
                    'blocked_at' => 0.0,
                    'duration' => null,
                    'permanent' => true,
                ];
                continue;
            }

            if (!is_array($row)) {
                continue;
            }

            $ip = isset($row['ip']) ? (string) $row['ip'] : '';
            if ($ip === '') {
                continue;
            }

            $duration = null;
            if (array_key_exists('duration', $row) && $row['duration'] !== null) {
                $duration = (int) $row['duration'];
                if ($duration <= 0) {
                    $duration = null;
                }
            }

            $entries[] = [
                'ip' => $ip,
                'reason' => isset($row['reason']) ? (string) $row['reason'] : 'Manual block',
                'blocked_at' => isset($row['blocked_at']) ? (float) $row['blocked_at'] : 0.0,
                'duration' => $duration,
                'permanent' => isset($row['permanent']) ? (bool) $row['permanent'] : ($duration === null),
            ];
        }

        return $entries;
    }

    /**
     * @param array<int, array<string, mixed>> $entries
     */
    private static function writeEntries(string $path, array $entries): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($path, json_encode(array_values($entries), JSON_PRETTY_PRINT));
    }

    /**
     * @param array<int, array<string, mixed>> $entries
     * @return array<int, array<string, mixed>>
     */
    private static function activeEntries(array $entries): array
    {
        $now = microtime(true);
        $active = [];
        foreach ($entries as $entry) {
            if (self::isEntryActive($entry, $now)) {
                $active[] = $entry;
            }
        }

        return $active;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function isEntryActive(array $entry, float $now): bool
    {
        $permanent = (bool) ($entry['permanent'] ?? false);
        if ($permanent) {
            return true;
        }

        $duration = isset($entry['duration']) ? (int) $entry['duration'] : 0;
        if ($duration <= 0) {
            return false;
        }

        $blockedAt = isset($entry['blocked_at']) ? (float) $entry['blocked_at'] : 0.0;
        return ($blockedAt + $duration) > $now;
    }
}
