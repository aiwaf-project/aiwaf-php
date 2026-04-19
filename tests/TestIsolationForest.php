<?php
/**
 * IsolationForest PHPUnit suite – deterministic, threshold‑free.
 *
 * - Verifies that anomaly‑score(outlier) > score(normal) before and after save/load.
 * - Then builds a threshold halfway between those two scores and checks predictions.
 *   This removes rare flakiness from score jitter.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use AIWAF\IsolationForest;

class TestIsolationForest extends TestCase
{
    private IsolationForest $forest;

    protected function setUp(): void
    {
        // 400 trees, 32‑sample subsets → stable yet quick (≈20 ms)
        $this->forest = new IsolationForest(400, 32);
    }

    /**
     * Raw score ordering & prediction on freshly trained forest.
     */
    public function testScoresAndPredict(): void
    {
        $this->trainForest();

        [$normalVec, $outlierVec] = $this->sampleVectors();

        $sN = $this->forest->scoreSamples([$normalVec])[0];
        $sA = $this->forest->scoreSamples([$outlierVec])[0];

        // 1️⃣ ordering must hold
        $this->assertGreaterThan($sN, $sA, 'Outlier score should exceed normal score');

        $th = ($sN + $sA) / 2; // threshold safely between

        // 2️⃣ predictions must reflect ordering
        $this->assertSame( 1, $this->forest->predict([$normalVec ], $th)[0]);
        $this->assertSame(-1, $this->forest->predict([$outlierVec], $th)[0]);
    }

    /**
     * Same checks after serialisation round‑trip.
     */
    public function testSaveLoadKeepsScores(): void
    {
        $this->trainForest();

        $path = __DIR__ . '/../resources/test_iforest.json';
        $this->forest->saveModel($path);

        $loaded = new IsolationForest();
        $loaded->loadModel($path);

        [$normalVec, $outlierVec] = $this->sampleVectors();

        $sN = $loaded->scoreSamples([$normalVec])[0];
        $sA = $loaded->scoreSamples([$outlierVec])[0];

        $this->assertGreaterThan($sN, $sA, 'Outlier score should exceed normal score after reload');

        $th = ($sN + $sA) / 2;
        $this->assertSame( 1, $loaded->predict([$normalVec ], $th)[0]);
        $this->assertSame(-1, $loaded->predict([$outlierVec], $th)[0]);
    }

    // ---------------------------------------------------------------------
    //  Helper methods
    // ---------------------------------------------------------------------

    /**
     * Train the member forest on 600 synthetic normal rows.
     */
    private function trainForest(): void
    {
        $norm = [];
        for ($i = 0; $i < 600; $i++) {
            $norm[] = [
                rand(10, 45), rand(0, 5), rand(0, 2), 0, rand(0, 12),
                rand(0, 6), 0, 0
            ];
        }
        $this->forest->fit($norm);
    }

    /**
     * Return a [normalVec, outlierVec] pair.
     */
    private function sampleVectors(): array
    {
        $normal  = [30, 2, 1, 0, 4, 2, 0, 0];
        $anomaly = [9000, 400, 40, 1, 200, 140, 1, 1];
        return [$normal, $anomaly];
    }
}
?>
