<?php
namespace AIWAF\Adapters;

use AIWAF\RateLimit\DbDriver;
use AIWAF\RateLimit\DriverInterface;

class DbAdapter implements RateLimitAdapterInterface
{
    private \PDO $pdo;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function createDriver(): DriverInterface
    {
        return new DbDriver($this->pdo);
    }
}
