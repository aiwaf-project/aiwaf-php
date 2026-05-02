<?php

declare(strict_types=1);

use AIWAF\Core\RuntimeUtils;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestRuntimeUtilsParity extends TestCase
{
    public function testGetRequestPathStripsQueryString(): void
    {
        $path = RuntimeUtils::getRequestPath(['REQUEST_URI' => '/api/orders?id=10&sort=asc']);
        $this->assertSame('/api/orders', $path);
    }

    public function testGetIpFromHeadersFallsBackToForwardedWhenRemoteAddrIsProxyLike(): void
    {
        $ip = RuntimeUtils::getIpFromHeaders([
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.9, 10.0.0.3',
        ]);

        $this->assertSame('203.0.113.9', $ip);
    }

    public function testGetIpFromHeadersReturnsSafeDefaultWhenNoIpPresent(): void
    {
        $ip = RuntimeUtils::getIpFromHeaders([]);
        $this->assertSame('0.0.0.0', $ip);
    }

    public function testIsProxyLikeIpForIpv6LocalAndLinkLocal(): void
    {
        $this->assertTrue(RuntimeUtils::isProxyLikeIp('::1'));
        $this->assertTrue(RuntimeUtils::isProxyLikeIp('fe80::1'));
    }

    public function testIsPrivateIpDoesNotTreatDocumentationRangesAsPrivate(): void
    {
        $this->assertFalse(RuntimeUtils::isPrivateIp('203.0.113.10'));
        $this->assertFalse(RuntimeUtils::isPrivateIp('198.51.100.42'));
        $this->assertTrue(RuntimeUtils::isPrivateIp('10.0.0.1'));
    }
}
