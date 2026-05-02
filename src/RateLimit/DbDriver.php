<?php
namespace AIWAF\RateLimit;

class DbDriver implements DriverInterface
{
    private \PDO $pdo;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function increment(string $ip, int $periodSeconds): int
    {
        $period = gmdate('YmdHi');
        $driver = strtolower((string) $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME));
        if ($driver === 'sqlite') {
            $stmt = $this->pdo->prepare(
                "INSERT INTO ratelimit (ip, period, cnt)
                 VALUES (:ip, :period, 1)
                 ON CONFLICT(ip, period) DO UPDATE SET cnt = cnt + 1"
            );
            $stmt->execute(['ip' => $ip, 'period' => $period]);
        } else {
            $stmt = $this->pdo->prepare(
                "INSERT INTO ratelimit (ip, period, cnt)
                 VALUES (:ip, :period, 1)
                 ON DUPLICATE KEY UPDATE cnt = cnt + 1"
            );
            $stmt->execute(['ip' => $ip, 'period' => $period]);
        }

        $stmt = $this->pdo->prepare(
            "SELECT cnt FROM ratelimit WHERE ip = :ip AND period = :period"
        );
        $stmt->execute(['ip' => $ip, 'period' => $period]);
        return (int) $stmt->fetchColumn();
    }
}
