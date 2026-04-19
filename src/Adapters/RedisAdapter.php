<?php
namespace AIWAF\Adapters;

use AIWAF\RateLimit\DriverInterface;
use AIWAF\RateLimit\RedisDriver;
use Redis;

class RedisAdapter implements RateLimitAdapterInterface
{
    private Redis $redis;

    public function __construct(Redis $redis)
    {
        $this->redis = $redis;
    }

    public function createDriver(): DriverInterface
    {
        return new RedisDriver($this->redis);
    }
}
