<?php

declare(strict_types=1);

use AIWAF\Adapters\ApcuAdapter;
use AIWAF\Adapters\DbAdapter;
use AIWAF\Adapters\InMemoryAdapter;
use AIWAF\Adapters\RedisAdapter;
use AIWAF\RateLimit\ApcuDriver;
use AIWAF\RateLimit\DbDriver;
use AIWAF\RateLimit\DriverInterface;
use AIWAF\RateLimit\InMemoryDriver;
use AIWAF\RateLimit\RedisDriver;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestAdaptersParity extends TestCase
{
    public function testInMemoryAdapterCreatesInMemoryDriver(): void
    {
        $adapter = new InMemoryAdapter();
        $driver = $adapter->createDriver();

        $this->assertInstanceOf(InMemoryDriver::class, $driver);
        $this->assertInstanceOf(DriverInterface::class, $driver);
    }

    public function testInMemoryDriverIncrementCountsPerIpAndWindow(): void
    {
        $driver = (new InMemoryAdapter())->createDriver();

        $this->assertSame(1, $driver->increment('203.0.113.10', 60));
        $this->assertSame(2, $driver->increment('203.0.113.10', 60));
        $this->assertSame(1, $driver->increment('203.0.113.11', 60));
    }

    public function testApcuAdapterCreatesApcuDriver(): void
    {
        $adapter = new ApcuAdapter();
        $driver = $adapter->createDriver();

        $this->assertInstanceOf(ApcuDriver::class, $driver);
        $this->assertInstanceOf(DriverInterface::class, $driver);
    }

    public function testApcuDriverIncrementWhenApcuCliEnabled(): void
    {
        if (!function_exists('apcu_add') || !function_exists('apcu_inc')) {
            $this->markTestSkipped('APCu functions are not available in this PHP runtime.');
        }

        $apcEnabled = (string) ini_get('apc.enabled');
        $apcCliEnabled = (string) ini_get('apc.enable_cli');
        if ($apcEnabled !== '1' || $apcCliEnabled !== '1') {
            $this->markTestSkipped('APCu is not enabled for CLI runtime.');
        }

        $driver = (new ApcuAdapter())->createDriver();
        $ip = '198.51.100.' . random_int(10, 200);

        $this->assertSame(1, $driver->increment($ip, 120));
        $this->assertSame(2, $driver->increment($ip, 120));
    }

    public function testDbAdapterCreatesDbDriver(): void
    {
        $pdo = $this->getMockBuilder(PDO::class)
            ->disableOriginalConstructor()
            ->getMock();

        $adapter = new DbAdapter($pdo);
        $driver = $adapter->createDriver();

        $this->assertInstanceOf(DbDriver::class, $driver);
        $this->assertInstanceOf(DriverInterface::class, $driver);
    }

    public function testDbDriverIncrementExecutesUpsertAndReturnsLatestCount(): void
    {
        $upsertStmt = $this->createMock(PDOStatement::class);
        $selectStmt = $this->createMock(PDOStatement::class);

        $upsertStmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(static function (array $params): bool {
                return isset($params['ip'], $params['period'])
                    && $params['ip'] === '203.0.113.55'
                    && is_string($params['period'])
                    && strlen($params['period']) === 12;
            }))
            ->willReturn(true);

        $selectStmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(static function (array $params): bool {
                return isset($params['ip'], $params['period'])
                    && $params['ip'] === '203.0.113.55'
                    && is_string($params['period'])
                    && strlen($params['period']) === 12;
            }))
            ->willReturn(true);

        $selectStmt->expects($this->once())
            ->method('fetchColumn')
            ->willReturn('7');

        $pdo = $this->getMockBuilder(PDO::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['prepare'])
            ->getMock();

        $pdo->expects($this->exactly(2))
            ->method('prepare')
            ->willReturnOnConsecutiveCalls($upsertStmt, $selectStmt);

        $driver = new DbDriver($pdo);
        $count = $driver->increment('203.0.113.55', 60);

        $this->assertSame(7, $count);
    }

    public function testDbDriverIncrementBubblesPdoExceptionOnPrepareFailure(): void
    {
        $pdo = $this->getMockBuilder(PDO::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['prepare'])
            ->getMock();

        $pdo->expects($this->once())
            ->method('prepare')
            ->willThrowException(new PDOException('prepare failed'));

        $driver = new DbDriver($pdo);

        $this->expectException(PDOException::class);
        $this->expectExceptionMessage('prepare failed');
        $driver->increment('203.0.113.99', 60);
    }

    public function testRedisAdapterCreatesRedisDriverWhenExtensionIsAvailable(): void
    {
        if (!class_exists('Redis')) {
            $this->markTestSkipped('Redis extension is not available in this PHP runtime.');
        }

        $redis = $this->createMock('Redis');
        $adapter = new RedisAdapter($redis);
        $driver = $adapter->createDriver();

        $this->assertInstanceOf(RedisDriver::class, $driver);
        $this->assertInstanceOf(DriverInterface::class, $driver);
    }

    public function testRedisDriverIncrementSetsExpiryOnFirstHit(): void
    {
        if (!class_exists('Redis')) {
            $this->markTestSkipped('Redis extension is not available in this PHP runtime.');
        }

        $redis = $this->createMock('Redis');
        $redis->expects($this->once())
            ->method('incr')
            ->with($this->callback(static function ($key): bool {
                return is_string($key) && str_starts_with($key, 'rl:198.51.100.77:');
            }))
            ->willReturn(1);

        $redis->expects($this->once())
            ->method('expire')
            ->with(
                $this->callback(static function ($key): bool {
                    return is_string($key) && str_starts_with($key, 'rl:198.51.100.77:');
                }),
                90
            )
            ->willReturn(true);

        $driver = new RedisDriver($redis);
        $this->assertSame(1, $driver->increment('198.51.100.77', 90));
    }

    public function testRedisDriverIncrementSkipsExpiryWhenCounterAlreadyExists(): void
    {
        if (!class_exists('Redis')) {
            $this->markTestSkipped('Redis extension is not available in this PHP runtime.');
        }

        $redis = $this->createMock('Redis');
        $redis->expects($this->once())
            ->method('incr')
            ->with($this->callback(static function ($key): bool {
                return is_string($key) && str_starts_with($key, 'rl:198.51.100.88:');
            }))
            ->willReturn(5);

        $redis->expects($this->never())->method('expire');

        $driver = new RedisDriver($redis);
        $this->assertSame(5, $driver->increment('198.51.100.88', 90));
    }

    public function testRedisDriverIncrementBubblesRedisExceptionFromIncr(): void
    {
        if (!class_exists('Redis')) {
            $this->markTestSkipped('Redis extension is not available in this PHP runtime.');
        }

        $redis = $this->createMock('Redis');
        $redis->expects($this->once())
            ->method('incr')
            ->willThrowException(new RuntimeException('redis unavailable'));

        $driver = new RedisDriver($redis);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('redis unavailable');
        $driver->increment('198.51.100.89', 90);
    }
}
