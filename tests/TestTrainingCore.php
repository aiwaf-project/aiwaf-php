<?php

declare(strict_types=1);

use AIWAF\Core\Training;
use AIWAF\Core\TrainingLogic;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestTrainingCore extends TestCase
{
    public function testIterBatchesNormalizesBatchSize(): void
    {
        $items = [1, 2, 3];
        $batches = Training::iterBatches($items, 0);

        $this->assertSame([[1], [2], [3]], $batches);
    }

    public function testExtractRustFeaturesParallelHandlesEmptyInput(): void
    {
        $result = Training::extractRustFeaturesParallel([], ['admin'], 10, 4, function (): array {
            return [['x']];
        });

        $this->assertSame([], $result);
    }

    public function testExtractRustFeaturesParallelSmallInputCallsExtractorOnce(): void
    {
        $calls = 0;
        $records = [['p' => '/a'], ['p' => '/b']];

        $result = Training::extractRustFeaturesParallel(
            $records,
            ['admin'],
            10,
            4,
            function (array $chunk, array $keywords) use (&$calls): array {
                $calls++;
                $this->assertSame(['admin'], $keywords);
                return [['count' => count($chunk)]];
            }
        );

        $this->assertSame(1, $calls);
        $this->assertSame([['count' => 2]], $result);
    }

    public function testExtractRustFeaturesParallelReturnsNullOnNullChunk(): void
    {
        $records = [['id' => 1], ['id' => 2], ['id' => 3], ['id' => 4]];

        $result = Training::extractRustFeaturesParallel(
            $records,
            ['admin'],
            2,
            2,
            function (array $chunk): ?array {
                if (($chunk[0]['id'] ?? 0) === 3) {
                    return null;
                }
                return $chunk;
            }
        );

        $this->assertNull($result);
    }

    public function testIsScanningPath(): void
    {
        $this->assertTrue(TrainingLogic::isScanningPath('/adminer/configuration'));
        $this->assertTrue(TrainingLogic::isScanningPath('/a/../../etc/passwd'));
        $this->assertFalse(TrainingLogic::isScanningPath('/products/list'));
    }

    public function testGetDefaultLegitimateKeywordsContainsCommonTerms(): void
    {
        $keywords = TrainingLogic::getDefaultLegitimateKeywords();

        $this->assertContains('profile', $keywords);
        $this->assertContains('dashboard', $keywords);
        $this->assertContains('api', $keywords);
    }

    public function testIsMaliciousContextReturnsFalseForKnownValidPath(): void
    {
        $result = TrainingLogic::isMaliciousContext(
            '/app/dashboard',
            'admin',
            '404',
            ['admin', 'config'],
            function (): bool {
                return true;
            }
        );

        $this->assertFalse($result);
    }

    public function testIsMaliciousContextDetectsExploitIndicators(): void
    {
        $result = TrainingLogic::isMaliciousContext(
            '/x/../..//backup/database/dump?x=union+select',
            'config',
            '404',
            ['admin', 'config', 'backup'],
            null
        );

        $this->assertTrue($result);
    }
}
