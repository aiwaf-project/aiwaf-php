<?php
namespace AIWAF\Core;

class KeywordFallbackStore
{
    private string $storagePath;

    public function __construct(string $storagePath)
    {
        $this->storagePath = $storagePath;
    }

    public function add(string $keyword, int $count = 1): void
    {
        $keywords = $this->load();
        if (!isset($keywords[$keyword])) {
            $keywords[$keyword] = 0;
        }
        $keywords[$keyword] += $count;
        $this->save($keywords);
    }

    public function remove(string $keyword): void
    {
        $keywords = $this->load();
        unset($keywords[$keyword]);
        $this->save($keywords);
    }

    public function all(): array
    {
        return $this->load();
    }

    public function top(int $n = 10): array
    {
        $keywords = $this->load();
        arsort($keywords);
        return array_slice($keywords, 0, $n, true);
    }

    private function load(): array
    {
        if (!file_exists($this->storagePath)) {
            return [];
        }

        $raw = file_get_contents($this->storagePath);
        $decoded = json_decode((string) $raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function save(array $keywords): void
    {
        $dir = dirname($this->storagePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        $lockPath = $this->storagePath . '.lock';
        $lock = fopen($lockPath, 'c');
        if ($lock === false) {
            throw new \RuntimeException('Unable to open keyword store lock file');
        }

        try {
            if (!flock($lock, LOCK_EX)) {
                throw new \RuntimeException('Unable to lock keyword store');
            }

            $tmp = $this->storagePath . '.' . uniqid('tmp_', true);
            $written = file_put_contents($tmp, json_encode($keywords, JSON_PRETTY_PRINT));
            if ($written === false) {
                @unlink($tmp);
                throw new \RuntimeException('Unable to write keyword store temp file');
            }

            if (!@rename($tmp, $this->storagePath)) {
                @unlink($tmp);
                throw new \RuntimeException('Unable to replace keyword store file');
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
