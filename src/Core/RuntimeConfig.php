<?php
namespace AIWAF\Core;

final class RuntimeConfig
{
    private array $config;

    public function __construct(array $overrides = [], ?string $configFile = null, bool $loadFromEnv = false)
    {
        $this->config = $this->getDefaultConfig();

        if ($configFile !== null && $configFile !== '') {
            $this->loadFromFile($configFile);
        }

        if ($loadFromEnv) {
            $this->loadFromEnvironment();
        }

        $this->update($overrides);
    }

    public function get(string $key, $default = null)
    {
        if (array_key_exists($key, $this->config)) {
            return $this->config[$key];
        }

        if (strpos($key, '.') === false) {
            return $default;
        }

        $segments = explode('.', $key);
        $value = $this->config;
        foreach ($segments as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    public function set(string $key, $value): void
    {
        if (strpos($key, '.') === false) {
            $this->config[$key] = $value;
            return;
        }

        $segments = explode('.', $key);
        $ref =& $this->config;
        foreach ($segments as $segment) {
            if (!isset($ref[$segment]) || !is_array($ref[$segment])) {
                $ref[$segment] = [];
            }
            $ref =& $ref[$segment];
        }
        $ref = $value;
    }

    public function update(array $updates): void
    {
        $this->config = $this->deepMerge($this->config, $updates);
    }

    public function loadFromFile(string $configFile): void
    {
        if (!file_exists($configFile)) {
            return;
        }

        $json = file_get_contents($configFile);
        $decoded = json_decode((string) $json, true);
        if (is_array($decoded)) {
            $this->update($decoded);
        }
    }

    public function loadFromEnvironment(): void
    {
        $mappings = [
            'AIWAF_STORAGE_BACKEND' => ['storage.backend', 'string'],
            'AIWAF_STORAGE_FILE_PATH' => ['storage.file_path', 'string'],
            'AIWAF_HEADER_VALIDATION_ENABLED' => ['header_validation.enabled', 'bool'],
            'AIWAF_HEADER_BLOCK_SUSPICIOUS' => ['header_validation.block_suspicious', 'bool'],
            'AIWAF_HEADER_QUALITY_THRESHOLD' => ['header_validation.quality_threshold', 'int'],
            'AIWAF_HEADER_EXEMPT_PATHS' => ['header_validation.exempt_paths', 'list'],
            'AIWAF_RATE_LIMITING_ENABLED' => ['rate_limiting.enabled', 'bool'],
            'AIWAF_RATE_MAX_REQUESTS' => ['rate_limiting.max_requests', 'int'],
            'AIWAF_RATE_WINDOW_SECONDS' => ['rate_limiting.window_seconds', 'int'],
            'AIWAF_EXEMPT_IPS' => ['rate_limiting.exempt_ips', 'list'],
            'AIWAF_IP_KEYWORD_BLOCK_ENABLED' => ['ip_keyword_block.enabled', 'bool'],
            'AIWAF_HONEYPOT_ENABLED' => ['honeypot.enabled', 'bool'],
            'AIWAF_GEO_BLOCK_ENABLED' => ['geo_block.enabled', 'bool'],
            'AIWAF_GEO_ALLOW_COUNTRIES' => ['geo_block.allow_countries', 'list'],
            'AIWAF_GEO_BLOCK_COUNTRIES' => ['geo_block.block_countries', 'list'],
            'AIWAF_AI_ANOMALY_ENABLED' => ['ai_anomaly.enabled', 'bool'],
            'AIWAF_UUID_TAMPER_ENABLED' => ['uuid_tamper.enabled', 'bool'],
            'AIWAF_LOGGING_MIDDLEWARE_ENABLED' => ['logging_middleware.enabled', 'bool'],
            'AIWAF_BLACKLIST_DEFAULT_DURATION' => ['blacklist.default_block_duration', 'int'],
            'AIWAF_BLACKLIST_PERMANENT_THRESHOLD' => ['blacklist.permanent_block_threshold', 'int'],
            'AIWAF_BLACKLIST_AUTO_UNBLOCK' => ['blacklist.auto_unblock_enabled', 'bool'],
            'AIWAF_LOG_LEVEL' => ['logging.level', 'string'],
            'AIWAF_LOG_FILE' => ['logging.log_file', 'string'],
            'AIWAF_AI_ANOMALY_THRESHOLD' => ['ai_anomaly_threshold', 'float'],
        ];

        foreach ($mappings as $env => $target) {
            $raw = getenv($env);
            if ($raw === false) {
                continue;
            }

            [$path, $type] = $target;
            $value = $this->parseEnvValue((string) $raw, (string) $type);
            $this->set((string) $path, $value);
        }
    }

    /**
     * @return array<int, string>
     */
    public function validate(): array
    {
        $errors = [];

        $backend = (string) $this->get('storage.backend', '');
        if (!in_array($backend, ['memory', 'file', 'csv', 'db'], true)) {
            $errors[] = 'Invalid storage backend: ' . $backend;
        }

        $checks = [
            ['header_validation.quality_threshold', 0, 20],
            ['rate_limiting.max_requests', 1, 10000],
            ['rate_limiting.window_seconds', 1, 86400],
            ['blacklist.default_block_duration', 60, 86400 * 7],
            ['blacklist.permanent_block_threshold', 1, 100],
            ['security.max_header_length', 1024, 65536],
        ];

        foreach ($checks as $check) {
            [$key, $min, $max] = $check;
            $value = $this->get((string) $key);
            if (!is_int($value) || $value < $min || $value > $max) {
                $errors[] = 'Invalid ' . $key . ': must be integer between ' . $min . ' and ' . $max;
            }
        }

        $level = (string) $this->get('logging.level', '');
        if (!in_array($level, ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], true)) {
            $errors[] = 'Invalid log level: ' . $level;
        }

        return $errors;
    }

    public function isEnabled(string $feature): bool
    {
        return (bool) $this->get($feature . '.enabled', false);
    }

    public function enableFeature(string $feature): void
    {
        $this->set($feature . '.enabled', true);
    }

    public function disableFeature(string $feature): void
    {
        $this->set($feature . '.enabled', false);
    }

    public function toArray(): array
    {
        return $this->config;
    }

    private function getDefaultConfig(): array
    {
        return [
            'exempt_paths' => Defaults::EXEMPT_PATHS,
            'rate_limit_per_minute' => 60,
            'keyword_detection_threshold' => 5,
            'uuid_tamper_threshold' => 3,
            'ai_anomaly_threshold' => 0.65,
            'header_min_score' => 3,
            'required_headers' => ['HTTP_USER_AGENT', 'HTTP_ACCEPT'],
            'blocked_ips_path' => dirname(__DIR__, 2) . '/resources/blocked_ips.json',
            'keyword_store_path' => dirname(__DIR__, 2) . '/resources/dynamic_keywords.json',
            'storage' => [
                'backend' => 'memory',
                'file_path' => 'aiwaf_data.json',
            ],
            'header_validation' => [
                'enabled' => true,
                'block_suspicious' => true,
                'quality_threshold' => 3,
                'exempt_paths' => ['/health', '/healthz', '/status', '/ping', '/metrics', '/favicon.ico', '/robots.txt'],
                'custom_suspicious_patterns' => [],
                'custom_legitimate_patterns' => [],
                'trust_legitimate_bots' => false,
            ],
            'rate_limiting' => [
                'enabled' => true,
                'max_requests' => 20,
                'window_seconds' => 10,
                'flood_threshold' => 40,
                'exempt_ips' => [],
            ],
            'ip_keyword_block' => [
                'enabled' => true,
                'malicious_keywords' => [
                    '.env', '.git', '.bak', 'shell', 'filemanager',
                ],
            ],
            'honeypot' => [
                'enabled' => true,
                'min_form_time' => 1.0,
            ],
            'geo_block' => [
                'enabled' => false,
                'allow_countries' => [],
                'block_countries' => [],
            ],
            'ai_anomaly' => [
                'enabled' => true,
            ],
            'uuid_tamper' => [
                'enabled' => true,
            ],
            'logging_middleware' => [
                'enabled' => true,
                'log_dir' => 'aiwaf_logs',
                'log_format' => 'combined',
            ],
            'blacklist' => [
                'default_block_duration' => 3600,
                'permanent_block_threshold' => 5,
                'auto_unblock_enabled' => true,
                'cleanup_interval' => 3600,
            ],
            'exemptions' => [
                'private_ips_exempted' => true,
                'localhost_exempted' => true,
                'auto_exempt_patterns' => [
                    '127.0.0.1',
                    '::1',
                    '192.168.*.*',
                    '10.*.*.*',
                    '172.16.*.*',
                ],
            ],
            'security' => [
                'log_blocked_requests' => true,
                'log_suspicious_requests' => true,
                'max_header_length' => 8192,
                'max_user_agent_length' => 512,
            ],
            'logging' => [
                'level' => 'INFO',
                'format' => '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'log_file' => null,
            ],
            'path_rules' => [],
        ];
    }

    private function parseEnvValue(string $value, string $type)
    {
        if ($type === 'bool') {
            return in_array(strtolower($value), ['true', '1', 'yes', 'on'], true);
        }

        if ($type === 'int') {
            return (int) $value;
        }

        if ($type === 'float') {
            return (float) $value;
        }

        if ($type === 'list') {
            $parts = array_map('trim', explode(',', $value));
            return array_values(array_filter($parts, static function ($part): bool {
                return $part !== '';
            }));
        }

        return $value;
    }

    private function deepMerge(array $base, array $update): array
    {
        foreach ($update as $key => $value) {
            if (isset($base[$key]) && is_array($base[$key]) && is_array($value)) {
                $base[$key] = $this->deepMerge($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }

        return $base;
    }
}
