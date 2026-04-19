<?php
require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use AIWAF\IPBlocker;
use AIWAF\Config;

class TestIPBlocker extends TestCase
{
    private ?string $backup = null;

    protected function setUp(): void
    {
        $path = Config::BLOCKED_IPS_PATH;
        if (file_exists($path)) {
            $content = file_get_contents($path);
            $this->backup = $content === false ? null : $content;
        } else {
            $this->backup = null;
        }
    }

    protected function tearDown(): void
    {
        $path = Config::BLOCKED_IPS_PATH;
        if ($this->backup === null) {
            @unlink($path);
            return;
        }

        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        file_put_contents($path, $this->backup);
    }

    public function testBlockUnblockIp(): void
    {
        $ip = '192.0.2.1';
        IPBlocker::blockPermanentIp($ip, 'unit-test');

        $blockedIps = IPBlocker::getBlockedIps();
        $this->assertContains($ip, $blockedIps);

        $info = IPBlocker::getBlockedInfo($ip);
        $this->assertIsArray($info);
        $this->assertSame($ip, $info['ip'] ?? null);
        $this->assertSame('unit-test', $info['reason'] ?? null);
        $this->assertTrue((bool) ($info['permanent'] ?? false));

        IPBlocker::unblockIp($ip);
        $this->assertFalse(IPBlocker::isBlocked($ip));
    }

    public function testLegacyFlatArrayFormatStillWorks(): void
    {
        $path = Config::BLOCKED_IPS_PATH;
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($path, json_encode(['203.0.113.9'], JSON_PRETTY_PRINT));
        $this->assertTrue(IPBlocker::isBlocked('203.0.113.9'));

        $info = IPBlocker::getBlockedInfo('203.0.113.9');
        $this->assertIsArray($info);
        $this->assertSame('Legacy block', $info['reason'] ?? null);
        $this->assertTrue((bool) ($info['permanent'] ?? false));
    }

    public function testTemporaryBlockExpires(): void
    {
        $ip = '198.51.100.77';
        IPBlocker::blockTemporaryIp($ip, 'temp-test', 1);

        $this->assertTrue(IPBlocker::isBlocked($ip));
        usleep(1200000);
        $this->assertFalse(IPBlocker::isBlocked($ip));
    }
}
