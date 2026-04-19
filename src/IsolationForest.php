<?php
namespace AIWAF;

class IsolationForest
{
    private array $trees = [];
    private int $nTrees;
    private int $sampleSize;

    public function __construct(int $nTrees = 100, int $sampleSize = 256)
    {
        $this->nTrees = $nTrees;
        $this->sampleSize = $sampleSize;
    }

    public function fit(array $X): void
    {
        for ($i = 0; $i < $this->nTrees; $i++) {
            $sample = $this->randomSample($X, $this->sampleSize);
            $this->trees[] = $this->buildTree($sample);
        }
    }

    private function buildTree(array $X, int $depth = 0)
    {
        if (count($X) <= 1 || $depth > log(count($X) + 1, 2)) {
            return null;
        }
    
        $firstRow = reset($X);
        if (empty($firstRow)) {
            return null;
        }
    
        $featureIndex = array_rand($firstRow);
        $featureValues = array_column($X, $featureIndex);
    
        $min = min($featureValues);
        $max = max($featureValues);
    
        if ($min === $max) {
            return null;
        }
    
        $splitValue = $min + (mt_rand() / mt_getrandmax()) * ($max - $min);
    
        $left = array_filter($X, fn($row) => $row[$featureIndex] < $splitValue);
        $right = array_filter($X, fn($row) => $row[$featureIndex] >= $splitValue);
    
        if (empty($left) || empty($right)) {
            return null; // no point splitting further
        }
    
        return [
            'feature' => $featureIndex,
            'split' => $splitValue,
            'left' => $this->buildTree($left, $depth + 1),
            'right' => $this->buildTree($right, $depth + 1),
        ];
    }
    

    private function randomSample(array $X, int $size): array
    {
        if (count($X) <= $size) {
            return $X;
        }
    
        $keys = array_rand($X, $size);
        $keys = is_array($keys) ? $keys : [$keys];
        return array_map(fn($k) => $X[$k], $keys);
    }
    

    public function pathLength(array $row, $tree, int $depth = 0): int
    {
        if ($tree === null) {
            return $depth;
        }

        $feature = $tree['feature'];
        $split = $tree['split'];

        if ($row[$feature] < $split) {
            return $this->pathLength($row, $tree['left'], $depth + 1);
        }
        return $this->pathLength($row, $tree['right'], $depth + 1);
    }

    public function scoreSamples(array $X): array
    {
        $scores = [];
        foreach ($X as $row) {
            $paths = array_map(fn($tree) => $this->pathLength($row, $tree), $this->trees);
            $avgPath = array_sum($paths) / count($paths);
            $scores[] = $this->anomalyScore($avgPath);
        }
        return $scores;
    }

    private function anomalyScore(float $avgPathLength): float
    {
        $c = 2 * (log($this->sampleSize - 1) + 0.5772) - (2 * ($this->sampleSize - 1) / $this->sampleSize);
        return pow(2, -$avgPathLength / $c);
    }

    public function predict(array $X, float $threshold = 0.8): array
    {
        $scores = $this->scoreSamples($X);
        //  score > threshold  ⇒ anomaly  (return –1)
        return array_map(
            fn($s) => $s > $threshold ? -1 : 1,
            $scores
        );
    }
    

    public function saveModel(string $path): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        $lockPath = $path . '.lock';
        $lock = fopen($lockPath, 'c');
        if ($lock === false) {
            throw new \RuntimeException('Unable to open model lock file: ' . $lockPath);
        }

        try {
            if (!flock($lock, LOCK_EX)) {
                throw new \RuntimeException('Unable to lock model file: ' . $path);
            }

            $tmp = $path . '.' . uniqid('tmp_', true);
            $payload = json_encode($this->trees, JSON_PRETTY_PRINT);
            if (file_put_contents($tmp, $payload) === false) {
                @unlink($tmp);
                throw new \RuntimeException('Unable to write model temp file: ' . $tmp);
            }

            if (!@rename($tmp, $path)) {
                @unlink($tmp);
                throw new \RuntimeException('Unable to replace model file: ' . $path);
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function loadModel(string $path): void
    {
        $this->trees = json_decode(file_get_contents($path), true);
    }
}

?>
