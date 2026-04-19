<?php

declare(strict_types=1);

use AIWAF\Core\Exemptions;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestExemptionsParity extends TestCase
{
    public function testNormalizePathHandlesCaseAndSlashes(): void
    {
        $this->assertSame('/api/v1/', Exemptions::normalizePath('API//V1/'));
        $this->assertSame('/', Exemptions::normalizePath(''));
        $this->assertSame('/health/', Exemptions::normalizePath('health', true));
        $this->assertSame('/health', Exemptions::normalizePath('/health/', false));
    }

    public function testIsPathExemptSupportsExactPrefixAndWildcard(): void
    {
        $exempt = ['/health', '/assets/', '*.css', '/.well-known/*'];

        $this->assertTrue(Exemptions::isPathExempt('/health', $exempt));
        $this->assertTrue(Exemptions::isPathExempt('/assets/app.js', $exempt));
        $this->assertTrue(Exemptions::isPathExempt('/styles/main.css', $exempt));
        $this->assertTrue(Exemptions::isPathExempt('/.well-known/security.txt', $exempt));
        $this->assertFalse(Exemptions::isPathExempt('/admin/login', $exempt));
    }

    public function testIsPathExemptCanDisablePrefixOrWildcardModes(): void
    {
        $this->assertFalse(Exemptions::isPathExempt('/assets/app.js', ['/assets'], true, false));
        $this->assertFalse(Exemptions::isPathExempt('/styles/main.css', ['*.css'], false, true));
    }
}
