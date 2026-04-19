<?php
namespace AIWAF\Adapters;

use AIWAF\RateLimit\DriverInterface;
use AIWAF\RateLimit\InMemoryDriver;

class InMemoryAdapter implements RateLimitAdapterInterface
{
    public function createDriver(): DriverInterface
    {
        return new InMemoryDriver();
    }
}
