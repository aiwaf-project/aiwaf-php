<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use AIWAF\Adapters\InMemoryAdapter;
use AIWAF\Config;
use AIWAF\RateLimiter;
use AIWAF\RateLimit\InMemoryDriver;

class TestRateLimiter extends TestCase
{
    protected function setUp(): void
    {
        // Initialize with the in-memory driver
        RateLimiter::init(new InMemoryDriver());
    }

    public function testRateLimiting(): void
    {
        $ip = '127.0.0.1';

        // the first Config::$rateLimitPerMinute calls should pass
        for ($i = 1; $i <= Config::$rateLimitPerMinute; $i++) {
            $this->assertFalse(
                RateLimiter::check($ip),
                "Request #{$i} should NOT trigger rate limiting"
            );
        }

        // the very next request must be blocked
        $this->assertTrue(
            RateLimiter::check($ip),
            'Request exceeding the limit SHOULD trigger rate limiting'
        );
    }

    public function testRateLimiterViaAdapter(): void
    {
        RateLimiter::initAdapter(new InMemoryAdapter());

        $ip = '127.0.0.2';
        for ($i = 1; $i <= Config::$rateLimitPerMinute; $i++) {
            $this->assertFalse(RateLimiter::check($ip));
        }
        $this->assertTrue(RateLimiter::check($ip));
    }

    public function testRateLimiterRespectsCustomLimits(): void
    {
        RateLimiter::init(new InMemoryDriver());

        $ip = '127.0.0.3';
        $this->assertFalse(RateLimiter::check($ip, 2, 120));
        $this->assertFalse(RateLimiter::check($ip, 2, 120));
        $this->assertTrue(RateLimiter::check($ip, 2, 120));
    }
}
