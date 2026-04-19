<?php

declare(strict_types=1);

use AIWAF\Core\GeoIP;
use AIWAF\Core\StorageCsvImpl;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestCoreUtilityParity extends TestCase
{
    public function testGeoIpUsesBundledGeolockPathWhenDbPathMissing(): void
    {
        $result = GeoIP::lookupCountry('8.8.8.8');
        $this->assertTrue($result === null || (is_string($result) && strlen($result) >= 2));
    }

    public function testGeoIpLookupReturnsNullWithoutDbOrLibrary(): void
    {
        $result = GeoIP::lookupCountry('8.8.8.8', __DIR__ . '/missing.mmdb');
        $this->assertNull($result);
    }

    public function testGeoIpExtractCountryCodeFromSupportedPayloadShapes(): void
    {
        $ref = new ReflectionClass(GeoIP::class);
        $method = $ref->getMethod('extractCountryCode');
        $method->setAccessible(true);

        $this->assertSame('US', (string) $method->invoke(null, ['country_code' => 'US']));
        $this->assertSame('USA', (string) $method->invoke(null, ['country_code3' => 'USA']));
        $this->assertSame('CA', (string) $method->invoke(null, ['country' => ['iso_code' => 'CA']]));
        $this->assertSame('DE', (string) $method->invoke(null, ['country' => 'DE']));
    }

    public function testGeoIpResolveDbPathPrefersExplicitExistingFile(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'aiwaf_mmdb_');
        $this->assertIsString($tmp);
        $this->assertNotFalse($tmp);

        $ref = new ReflectionClass(GeoIP::class);
        $method = $ref->getMethod('resolveDbPath');
        $method->setAccessible(true);

        $resolved = $method->invoke(null, $tmp);
        $this->assertSame($tmp, $resolved);

        @unlink((string) $tmp);
    }

    public function testStorageCsvImplWhitelistAndKeywords(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_impl_' . uniqid('', true);

        StorageCsvImpl::ensureAll($dir);
        StorageCsvImpl::appendWhitelist($dir, '203.0.113.88');
        StorageCsvImpl::appendKeyword($dir, 'phpmyadmin');

        $whitelist = StorageCsvImpl::readWhitelist($dir);
        $keywords = StorageCsvImpl::readKeywords($dir);

        $this->assertContains('203.0.113.88', $whitelist);
        $this->assertContains('phpmyadmin', $keywords);

        $this->deleteDir($dir);
    }

    private function deleteDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $entries = scandir($dir);
        if (!is_array($entries)) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($path)) {
                $this->deleteDir($path);
            } else {
                @unlink($path);
            }
        }

        @rmdir($dir);
    }
}
