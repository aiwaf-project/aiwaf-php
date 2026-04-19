<?php
declare(strict_types=1);

// Pull in PHPUnit
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

use AIWAF\Logger;
use AIWAF\IsolationForest;

class TestLoggerAndIsolationForest extends TestCase
{
    private string $logFile;

    protected function setUp(): void
    {
        // Point Logger at a dedicated test file
        $this->logFile = __DIR__ . '/../resources/test_request_features.csv';
        Logger::setLogFile($this->logFile);

        // Ensure a clean slate
        if (file_exists($this->logFile)) {
            unlink($this->logFile);
        }
    }

    public function testLoggerWritesAndReads(): void
    {
        $vectors = [
            [1,2,3,4,5,6,7,8],
            [8,7,6,5,4,3,2,1],
        ];

        // Write two rows
        Logger::log($vectors[0]);
        Logger::log($vectors[1]);

        // Read them back
        $read = Logger::readAll();
        $this->assertCount(2, $read);
        $this->assertEquals($vectors[0], $read[0]);
        $this->assertEquals($vectors[1], $read[1]);
    }

    public function testForestTrainsAndPredictsOnLoggedData(): void
    {
        // Log 300 “normal” feature vectors
        for ($i = 0; $i < 300; $i++) {
            Logger::log([
                rand(10,20), rand(0,2), rand(0,1),
                0, rand(0,5), rand(0,3), 0, 0
            ]);
        }

        // Then log one extreme outlier
        $outlier = [5000,500,50,1,100,60,1,1];
        Logger::log($outlier);

        // Load them back
        $data = Logger::readAll();
        $this->assertCount(301, $data);

        // Train a robust forest
        $forest = new IsolationForest(200, 32);
        $forest->fit($data);

        // Score the very first normal row vs. the outlier
        $scores       = $forest->scoreSamples([$data[0], $outlier]);
        $normalScore  = $scores[0];
        $outlierScore = $scores[1];

        // 1) The outlier’s score must be strictly higher
        $this->assertGreaterThan(
            $normalScore,
            $outlierScore,
            'Outlier should score higher than normal'
        );

        // 2) Build a threshold in between
        $threshold = ($normalScore + $outlierScore) / 2;

        // 3) Finally predict with that threshold
        $preds = $forest->predict([$data[0], $outlier], $threshold);
        $this->assertSame( 1, $preds[0], 'Normal vector mis-classified' );
        $this->assertSame(-1, $preds[1], 'Outlier not flagged' );
    }
}
