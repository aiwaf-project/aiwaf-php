<?php

declare(strict_types=1);

require_once __DIR__ . '/../../../vendor/autoload.php';
require_once __DIR__ . '/../common/proxy_helpers.php';

use AIWAF\AIWAF;
use AIWAF\Adapters\InMemoryAdapter;
use AIWAF\Config;
use AIWAF\RateLimiter;

Config::$knownPaths = ['/wp-json', '/wp-content', '/wp-includes', '/wp-admin'];
RateLimiter::initAdapter(new InMemoryAdapter());
AIWAF::protect();

$targetBase = (string) getenv('TARGET_BASE_URL');
if ($targetBase !== '') {
    aiwaf_forward_to_target($targetBase);
    return;
}

echo 'AIWAF WordPress sandbox is running.';
