<?php

declare(strict_types=1);

use AIWAF\Adapters\DbAdapter;
use AIWAF\Adapters\RedisAdapter;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestAdapterIntegration extends TestCase
{
    public function testRedisAdapterWithRealRedisServer(): void
    {
        if (!class_exists('Redis')) {
            $this->markTestSkipped('Redis extension is not available in this PHP runtime.');
        }

        $host = getenv('AIWAF_TEST_REDIS_HOST');
        $port = (int) (getenv('AIWAF_TEST_REDIS_PORT') ?: '6379');
        if (!is_string($host) || trim($host) === '') {
            $this->markTestSkipped('Set AIWAF_TEST_REDIS_HOST to run Redis integration tests.');
        }

        $redis = new Redis();
        try {
            $connected = @$redis->connect($host, $port, 1.5);
        } catch (Throwable $e) {
            $connected = false;
        }

        if (!$connected) {
            $this->markTestSkipped('Redis server is not reachable for integration test.');
        }

        $adapter = new RedisAdapter($redis);
        $driver = $adapter->createDriver();

        $ip = '198.51.100.' . random_int(20, 200);
        $count1 = $driver->increment($ip, 120);
        $count2 = $driver->increment($ip, 120);

        $this->assertSame(1, (int) $count1);
        $this->assertSame(2, (int) $count2);
    }

    public function testDbAdapterWithRealMysql(): void
    {
        $dsn = getenv('AIWAF_TEST_DB_DSN');
        $user = getenv('AIWAF_TEST_DB_USER');
        $pass = getenv('AIWAF_TEST_DB_PASS');

        if (!is_string($dsn) || trim($dsn) === '') {
            $this->markTestSkipped('Set AIWAF_TEST_DB_DSN to run DB integration tests.');
        }

        try {
            $pdo = new PDO((string) $dsn, (string) ($user ?: ''), (string) ($pass ?: ''), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ]);
        } catch (Throwable $e) {
            $this->markTestSkipped('DB server is not reachable for integration test.');
            return;
        }

        $pdo->exec('CREATE TABLE IF NOT EXISTS ratelimit (
            ip VARCHAR(45) NOT NULL,
            period VARCHAR(12) NOT NULL,
            cnt INT NOT NULL DEFAULT 0,
            PRIMARY KEY (ip, period)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');

        $adapter = new DbAdapter($pdo);
        $driver = $adapter->createDriver();

        $ip = '203.0.113.' . random_int(20, 200);
        $count1 = $driver->increment($ip, 60);
        $count2 = $driver->increment($ip, 60);

        $this->assertSame(1, (int) $count1);
        $this->assertSame(2, (int) $count2);
    }
}
