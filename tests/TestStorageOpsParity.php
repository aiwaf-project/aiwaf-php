<?php

declare(strict_types=1);

use AIWAF\Core\StorageOps;
use AIWAF\Core\StorageSchema;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestStorageOpsParity extends TestCase
{
    public function testEnsureAndReadWriteCsvOps(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_csv_' . uniqid('', true);

        StorageOps::ensureCsvFiles($dir, StorageSchema::CSV_HEADERS);
        $this->assertFileExists($dir . DIRECTORY_SEPARATOR . StorageSchema::WHITELIST_CSV);

        StorageOps::appendCsvRow(
            $dir,
            StorageSchema::WHITELIST_CSV,
            ['203.0.113.10', StorageOps::nowIso()],
            StorageSchema::CSV_HEADERS
        );

        $set = StorageOps::readCsvSet($dir, StorageSchema::WHITELIST_CSV, 'ip', StorageSchema::CSV_HEADERS);
        $this->assertContains('203.0.113.10', $set);

        StorageOps::appendCsvRow(
            $dir,
            StorageSchema::BLACKLIST_CSV,
            ['198.51.100.1', 'scanner', StorageOps::nowIso(), '{}'],
            StorageSchema::CSV_HEADERS
        );

        $dict = StorageOps::readCsvDict($dir, StorageSchema::BLACKLIST_CSV, 'ip', 'reason', StorageSchema::CSV_HEADERS);
        $this->assertSame('scanner', $dict['198.51.100.1'] ?? null);

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
