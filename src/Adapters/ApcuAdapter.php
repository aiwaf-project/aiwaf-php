<?php
namespace AIWAF\Adapters;

use AIWAF\RateLimit\ApcuDriver;
use AIWAF\RateLimit\DriverInterface;

class ApcuAdapter implements RateLimitAdapterInterface
{
    public function createDriver(): DriverInterface
    {
        return new ApcuDriver();
    }
}
