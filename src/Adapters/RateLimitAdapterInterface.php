<?php
namespace AIWAF\Adapters;

use AIWAF\RateLimit\DriverInterface;

interface RateLimitAdapterInterface
{
    public function createDriver(): DriverInterface;
}
