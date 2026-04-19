<?php
require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use AIWAF\UUIDTamperProtector;

class TestUUIDTamperProtector extends TestCase
{
    public function testInvalidFormat()
    {
        $this->assertTrue(UUIDTamperProtector::isSuspicious('/invalid-path-not-uuid'));
    }

    public function testNonexistentUuid()
    {
        $this->assertTrue(UUIDTamperProtector::isSuspicious('/this/is/not/a/uuid'));
    }

    public function testValidUuidExists()
    {
        $validUuidPath = '/user/123e4567-e89b-12d3-a456-426614174000';
        $this->assertFalse(UUIDTamperProtector::isSuspicious($validUuidPath));
    }
}
