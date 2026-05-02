<?php

declare(strict_types=1);

use AIWAF\Core\RuntimeConfig;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestRuntimeConfigParity extends TestCase
{
    private array $savedEnv = [];

    protected function tearDown(): void
    {
        foreach ($this->savedEnv as $name => $value) {
            if ($value === false || $value === null) {
                putenv($name);
            } else {
                putenv($name . '=' . $value);
            }
        }
        $this->savedEnv = [];
    }

    public function testLoadsAndParsesEnvironmentValues(): void
    {
        $this->setEnv('AIWAF_RATE_MAX_REQUESTS', '99');
        $this->setEnv('AIWAF_HEADER_VALIDATION_ENABLED', 'false');
        $this->setEnv('AIWAF_HEADER_EXEMPT_PATHS', '/health,/status');
        $this->setEnv('AIWAF_AI_ANOMALY_THRESHOLD', '0.72');
        $this->setEnv('AIWAF_GEO_ALLOW_COUNTRIES', 'US,CA');
        $this->setEnv('AIWAF_GEO_BLOCK_COUNTRIES', 'RU,CN');
        $this->setEnv('AIWAF_EXEMPT_IPS', '203.0.113.1,198.51.100.0/24');
        $this->setEnv('AIWAF_RATE_LIMIT_BACKEND', 'db');
        $this->setEnv('AIWAF_RATE_LIMIT_DB_PATH', '/tmp/aiwaf-rate-limit.sqlite');

        $config = new RuntimeConfig([], null, true);

        $this->assertSame(99, $config->get('rate_limiting.max_requests'));
        $this->assertFalse($config->get('header_validation.enabled'));
        $this->assertSame(['/health', '/status'], $config->get('header_validation.exempt_paths'));
        $this->assertSame(0.72, $config->get('ai_anomaly_threshold'));
        $this->assertSame(['US', 'CA'], $config->get('geo_block.allow_countries'));
        $this->assertSame(['RU', 'CN'], $config->get('geo_block.block_countries'));
        $this->assertSame(['203.0.113.1', '198.51.100.0/24'], $config->get('rate_limiting.exempt_ips'));
        $this->assertSame('db', $config->get('rate_limiting.backend'));
        $this->assertSame('/tmp/aiwaf-rate-limit.sqlite', $config->get('rate_limiting.db_path'));
    }

    public function testLoadsFromFileAndMerges(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'aiwaf_cfg_');
        file_put_contents($path, json_encode([
            'rate_limiting' => ['window_seconds' => 21],
            'logging' => ['level' => 'DEBUG'],
        ]));

        $config = new RuntimeConfig([], $path, false);

        $this->assertSame(21, $config->get('rate_limiting.window_seconds'));
        $this->assertSame('DEBUG', $config->get('logging.level'));

        @unlink($path);
    }

    public function testValidateReturnsErrorsForInvalidValues(): void
    {
        $config = new RuntimeConfig([
            'storage' => ['backend' => 'invalid'],
            'rate_limiting' => ['max_requests' => 0],
            'logging' => ['level' => 'TRACE'],
        ], null, false);

        $errors = $config->validate();

        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('Invalid storage backend', implode(' | ', $errors));
    }

    private function setEnv(string $name, string $value): void
    {
        if (!array_key_exists($name, $this->savedEnv)) {
            $this->savedEnv[$name] = getenv($name);
        }
        putenv($name . '=' . $value);
    }
}
