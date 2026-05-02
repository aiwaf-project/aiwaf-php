<?php
namespace AIWAF;

use AIWAF\Adapters\RateLimitAdapterInterface;
use AIWAF\RateLimit\DriverInterface;
use AIWAF\RateLimit\InMemoryDriver;

class RateLimiter
{
    private static ?DriverInterface $driver = null;
    private const DEFAULT_WINDOW = 60;

    public static function init(DriverInterface $driver): void
    {
        self::$driver = $driver;
    }

    public static function initAdapter(RateLimitAdapterInterface $adapter): void
    {
        self::$driver = $adapter->createDriver();
    }

    public static function hasDriver(): bool
    {
        return self::$driver !== null;
    }

    public static function check(string $ip, ?int $maxRequests = null, ?int $windowSeconds = null): bool
    {
        if (self::$driver === null) {
            self::$driver = new InMemoryDriver();
        }

        $window = $windowSeconds !== null ? max(1, $windowSeconds) : self::DEFAULT_WINDOW;
        $max = $maxRequests !== null ? max(1, $maxRequests) : Config::$rateLimitPerMinute;

        $count = self::$driver->increment($ip, $window);
        return $count > $max;
    }
}
