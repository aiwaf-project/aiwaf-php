# AIWAF PHP

Adaptive, trainable web-application firewall middleware for PHP applications.

This README is an end-to-end guide: install, integrate, train, tune, validate, and operate.

## What You Get

- Header profile validation
- IP blocking and allowlisting helpers
- Rate limiting with pluggable backends
- Dynamic keyword detection
- UUID tamper checks
- Honeypot checks
- Isolation Forest anomaly scoring
- Log-based trainer with telemetry and route-awareness hooks

## Requirements

- PHP >= 7.4
- Composer
- Optional: ext-redis when using Redis adapters/drivers

## Package Configuration (Composer)

`composer.json` package-level defaults and scripts:

- Name: `aayushgauba/aiwaf`
- Type: `library`
- License: `MIT`
- Runtime dependency: `php >= 7.4`
- Suggested extension: `ext-redis` (only required for Redis adapter/driver)
- PSR-4 autoload: `AIWAF\\` -> `src/`
- Dev autoload: `AIWAF\\Tests\\` -> `tests/`
- Composer scripts:
	- `composer test`
	- `composer run cover-everything`
	- `composer run test-adapters-matrix`
	- `composer run validate-all`

## Install

```bash
composer require aayushgauba/aiwaf
```

## End-to-End Setup

### 1. Initialize resources

```bash
php setup.php
```

Runtime artifacts are stored under `resources/` by default:

- `blocked_ips.json`
- `dynamic_keywords.json`
- `request_features.csv`
- `forest_model.json`

### 2. Add protection to your bootstrap/front controller

Run AIWAF before output is sent.

```php
<?php
declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use AIWAF\AIWAF;
use AIWAF\RateLimiter;
use AIWAF\Adapters\InMemoryAdapter;

RateLimiter::initAdapter(new InMemoryAdapter());
AIWAF::protect();
```

### 3. (Optional) Configure known route prefixes to reduce false positives

```php
use AIWAF\Config;

Config::$knownPaths = ['/app', '/api/v1'];
```

### 4. Train from access logs

Set log location and run the trainer:

```powershell
$env:AIWAF_ACCESS_LOG = "C:\path\to\access.log"
php cli/detect_and_train.php
```

Linux/macOS:

```bash
export AIWAF_ACCESS_LOG=/var/log/nginx/access.log
php cli/detect_and_train.php
```

### 5. Verify artifacts and telemetry

- Check that `resources/forest_model.json` exists
- Check that `resources/dynamic_keywords.json` has learned entries
- Inspect trainer telemetry in logs or programmatically:

```php
use AIWAF\AIWAF;

$telemetry = AIWAF::getLastTrainingTelemetry();
```

## Runtime Backends

### In-memory

```php
use AIWAF\RateLimiter;
use AIWAF\Adapters\InMemoryAdapter;

RateLimiter::initAdapter(new InMemoryAdapter());
```

### APCu

```php
use AIWAF\RateLimiter;
use AIWAF\Adapters\ApcuAdapter;

RateLimiter::initAdapter(new ApcuAdapter());
```

### Redis

```php
use AIWAF\RateLimiter;
use AIWAF\Adapters\RedisAdapter;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
RateLimiter::initAdapter(new RedisAdapter($redis));
```

### PDO/DB

```php
use AIWAF\RateLimiter;
use AIWAF\Adapters\DbAdapter;

$pdo = new PDO('sqlite:' . __DIR__ . '/resources/aiwaf.sqlite');
RateLimiter::initAdapter(new DbAdapter($pdo));
```

## Trainer Inputs and Formats

The trainer auto-reads these sources from `AIWAF_ACCESS_LOG` and rotated variants:

- Plain access logs (`.log`)
- Rotated logs (`.log.1`, `.log.2`, ...)
- Gzip rotated logs (`.gz`)
- CSV logs (`.csv`, `.csv.gz`) with common fields like:
  - `timestamp`, `ip`, `method`, `path`, `status_code`, `response_time`

Parser coverage includes IPv4 and IPv6 client addresses.

## Route Awareness (Framework Adapter Hook)

Use a custom path-existence resolver for closer app parity.

```php
use AIWAF\AIWAF;

AIWAF::setPathExistsResolver(function (string $path): bool {
	$candidate = strtok($path, '?');
	return strpos('/' . ltrim((string) $candidate, '/'), '/app') === 0;
});
```

### Laravel snippet

```php
use AIWAF\AIWAF;
use Illuminate\Support\Facades\Route;

AIWAF::setPathExistsResolver(function (string $path): bool {
	$candidate = '/' . ltrim((string) strtok($path, '?'), '/');
	foreach (Route::getRoutes() as $route) {
		$uri = '/' . ltrim($route->uri(), '/');
		if ($candidate === $uri || strpos($candidate, $uri . '/') === 0) {
			return true;
		}
	}
	return false;
});
```

### Symfony snippet

```php
use AIWAF\AIWAF;
use Symfony\Component\Routing\RouterInterface;

/** @var RouterInterface $router */
AIWAF::setPathExistsResolver(function (string $path) use ($router): bool {
	$candidate = '/' . ltrim((string) strtok($path, '?'), '/');
	foreach ($router->getRouteCollection() as $route) {
		$routePath = (string) $route->getPath();
		if ($routePath !== '' && ($candidate === $routePath || strpos($candidate, rtrim($routePath, '/') . '/') === 0)) {
			return true;
		}
	}
	return false;
});
```

### WordPress snippet

```php
use AIWAF\AIWAF;

AIWAF::setPathExistsResolver(function (string $path): bool {
	$candidate = '/' . ltrim((string) strtok($path, '?'), '/');
	$known = ['/wp-json', '/wp-content', '/wp-includes'];
	foreach ($known as $prefix) {
		if ($candidate === $prefix || strpos($candidate, $prefix . '/') === 0) {
			return true;
		}
	}
	return false;
});
```

## Configuration Reference

AIWAF supports four configuration layers, applied in this order:

1. Runtime defaults (from `RuntimeConfig`)
2. Optional JSON config file (`RuntimeConfig::loadFromFile`)
3. Optional environment mapping (`RuntimeConfig::loadFromEnvironment`)
4. Runtime overrides passed in code (`RuntimeConfig::update`)

### Static Config API (`Config`)

You can set these before calling `AIWAF::protect()`:

- `Config::$exemptPaths`
- `Config::$knownPaths`
- `Config::$rateLimitPerMinute`
- `Config::$keywordDetectionThreshold`
- `Config::$uuidTamperThreshold`
- `Config::$aiAnomalyThreshold`
- `Config::HEADER_MIN_SCORE`
- `Config::REQUIRED_HEADERS`

### Environment Variables (RuntimeConfig Mapping)

These map directly into runtime keys:

- `AIWAF_STORAGE_BACKEND` -> `storage.backend`
- `AIWAF_STORAGE_FILE_PATH` -> `storage.file_path`
- `AIWAF_HEADER_VALIDATION_ENABLED` -> `header_validation.enabled`
- `AIWAF_HEADER_BLOCK_SUSPICIOUS` -> `header_validation.block_suspicious`
- `AIWAF_HEADER_QUALITY_THRESHOLD` -> `header_validation.quality_threshold`
- `AIWAF_HEADER_EXEMPT_PATHS` -> `header_validation.exempt_paths` (comma list)
- `AIWAF_RATE_LIMITING_ENABLED` -> `rate_limiting.enabled`
- `AIWAF_RATE_LIMIT_BACKEND` -> `rate_limiting.backend` (`memory|db|redis|apcu`)
- `AIWAF_RATE_MAX_REQUESTS` -> `rate_limiting.max_requests`
- `AIWAF_RATE_WINDOW_SECONDS` -> `rate_limiting.window_seconds`
- `AIWAF_EXEMPT_IPS` -> `rate_limiting.exempt_ips` (comma list)
- `AIWAF_RATE_LIMIT_DB_PATH` -> `rate_limiting.db_path`
- `AIWAF_RATE_LIMIT_REDIS_HOST` -> `rate_limiting.redis.host`
- `AIWAF_RATE_LIMIT_REDIS_PORT` -> `rate_limiting.redis.port`
- `AIWAF_RATE_LIMIT_REDIS_PASSWORD` -> `rate_limiting.redis.password`
- `AIWAF_RATE_LIMIT_REDIS_DATABASE` -> `rate_limiting.redis.database`
- `AIWAF_RATE_LIMIT_REDIS_TIMEOUT` -> `rate_limiting.redis.timeout`
- `AIWAF_IP_KEYWORD_BLOCK_ENABLED` -> `ip_keyword_block.enabled`
- `AIWAF_HONEYPOT_ENABLED` -> `honeypot.enabled`
- `AIWAF_GEO_BLOCK_ENABLED` -> `geo_block.enabled`
- `AIWAF_GEO_ALLOW_COUNTRIES` -> `geo_block.allow_countries` (comma list)
- `AIWAF_GEO_BLOCK_COUNTRIES` -> `geo_block.block_countries` (comma list)
- `AIWAF_AI_ANOMALY_ENABLED` -> `ai_anomaly.enabled`
- `AIWAF_UUID_TAMPER_ENABLED` -> `uuid_tamper.enabled`
- `AIWAF_LOGGING_MIDDLEWARE_ENABLED` -> `logging_middleware.enabled`
- `AIWAF_BLACKLIST_DEFAULT_DURATION` -> `blacklist.default_block_duration`
- `AIWAF_BLACKLIST_PERMANENT_THRESHOLD` -> `blacklist.permanent_block_threshold`
- `AIWAF_BLACKLIST_AUTO_UNBLOCK` -> `blacklist.auto_unblock_enabled`
- `AIWAF_LOG_LEVEL` -> `logging.level`
- `AIWAF_LOG_FILE` -> `logging.log_file`
- `AIWAF_AI_ANOMALY_THRESHOLD` -> `ai_anomaly_threshold`

### Environment Variables (Training/Telemetry Pipeline)

These are used by trainer/runtime logic outside RuntimeConfig mapping:

- `AIWAF_ACCESS_LOG` (required to train)
- `AIWAF_MIN_TRAIN_LOGS` (default `50`)
- `AIWAF_MIN_AI_LOGS` (default `10000`)
- `AIWAF_FORCE_AI_TRAINING` (`true|false`, default `false`)
- `AIWAF_DISABLE_AI` (`true|false`, bypass anomaly scoring at runtime)
- `AIWAF_FEATURE_LOG` (override feature CSV path)
- `AIWAF_KNOWN_PATHS` (comma-separated route prefixes)
- `AIWAF_PYTHON_FEATURE_BATCH_SIZE` (default `2000`)
- `AIWAF_PYTHON_PARALLEL_CHUNK_SIZE` (default batch size)
- `AIWAF_PYTHON_PARALLEL_WORKERS` (default `min(NUMBER_OF_PROCESSORS, 32)`)

### Default RuntimeConfig Keys

Main defaults (from `src/Core/RuntimeConfig.php`):

- `header_validation.enabled=true`
- `header_validation.block_suspicious=true`
- `header_validation.quality_threshold=3`
- `rate_limiting.enabled=true`
- `rate_limiting.backend=memory`
- `rate_limiting.max_requests=20`
- `rate_limiting.window_seconds=10`
- `ip_keyword_block.enabled=true`
- `honeypot.enabled=true`
- `geo_block.enabled=false`
- `ai_anomaly.enabled=true`
- `uuid_tamper.enabled=true`
- `logging_middleware.enabled=true`
- `blacklist.default_block_duration=3600`
- `blacklist.permanent_block_threshold=5`
- `blacklist.auto_unblock_enabled=true`
- `exemptions.private_ips_exempted=true`
- `exemptions.localhost_exempted=true`

Example JSON config file:

```json
{
	"header_validation": {
		"enabled": true,
		"block_suspicious": true,
		"quality_threshold": 3,
		"exempt_paths": ["/health", "/healthz"]
	},
	"rate_limiting": {
		"enabled": true,
		"max_requests": 20,
		"window_seconds": 10,
		"exempt_ips": []
	},
	"geo_block": {
		"enabled": false,
		"allow_countries": [],
		"block_countries": []
	},
	"ai_anomaly": {
		"enabled": true
	},
	"uuid_tamper": {
		"enabled": true
	}
}
```

## Operational Notes

- Model and keyword writes are lock-protected and atomically replaced.
- Trainer telemetry includes:
  - total lines, parse failures, parsed rows, feature rows
  - keyword candidate/learned counts
  - anomalous and blocked IP counts
  - top country summaries for anomalous/blocked IPs

## Testing

Run tests:

```bash
./vendor/bin/phpunit --colors=never --do-not-cache-result
```

Or with Composer:

```bash
composer test
```

Run full adapter matrix tests (Redis + APCu + MySQL-backed DB integration in Docker):

```bash
composer run test-adapters-matrix
```

Adapter matrix options:

- Retry flaky infra starts: `composer run test-adapters-matrix -- --retries=3`
- Skip image rebuild: `composer run test-adapters-matrix -- --no-build`
- Keep stack up for debugging: `composer run test-adapters-matrix -- --keep-up`

Keep adapter test containers running after the test command:

```bash
composer run test-adapters-matrix -- --keep-up
```

Run complete validation pipeline (unit + sandbox + adapter matrix):

```bash
composer run validate-all
```

Pipeline options:

- Repeat adapter matrix for stability checks: `composer run validate-all -- --repeat-adapter-matrix=5`
- Skip sandbox suite: `composer run validate-all -- --skip-cover-everything`
- Skip adapter matrix: `composer run validate-all -- --skip-adapter-matrix`

Run comprehensive verification (unit tests + sandbox end-to-end checks):

```bash
composer run cover-everything
```

Optional flags:

- Keep sandbox containers up after run: `composer run cover-everything -- --keep-up`
- Reuse already-running sandbox (skip compose up/down): `composer run cover-everything -- --skip-docker`
- Disable sandbox reset before run: `composer run cover-everything -- --no-reset-state`
- Increase compose startup retries: `composer run cover-everything -- --compose-retries=3`
- Force image rebuild during sandbox startup: `composer run cover-everything -- --build-sandbox`
- Tune thresholds:
	- `--max-normal-block-pct=5`
	- `--min-protected-attack-block-pct=80`
	- `--max-direct-attack-block-pct=15`
	- `--max-protected-parity-gap-pct=1`

## Troubleshooting

- No model generated:
  - ensure `AIWAF_ACCESS_LOG` points to a readable log file
  - lower `AIWAF_MIN_TRAIN_LOGS` for small datasets
- Too many blocks:
  - raise `AIWAF_AI_ANOMALY_THRESHOLD`
  - add route prefixes via `AIWAF_KNOWN_PATHS` or resolver hook
- Not enough detections:
  - lower `AIWAF_AI_ANOMALY_THRESHOLD`
  - retrain with more representative logs

## License

MIT
