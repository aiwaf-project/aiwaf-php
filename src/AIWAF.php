<?php
namespace AIWAF;

use AIWAF\Adapters\ApcuAdapter;
use AIWAF\Adapters\DbAdapter;
use AIWAF\Adapters\InMemoryAdapter;
use AIWAF\Adapters\RedisAdapter;
use AIWAF\Core\Constants;
use AIWAF\Core\Exemptions;
use AIWAF\Core\GeoIP;
use AIWAF\Core\HeaderValidation;
use AIWAF\Core\Logs;
use AIWAF\Core\RuntimeUtils;
use AIWAF\Core\RuntimeConfig;
use AIWAF\Core\TrainingLogic;

class AIWAF
{
    private const HARD_MIN_AI_LOG_LINES = 10000;
    private const RUNTIME_MIN_KW_HITS_FOR_AI_BLOCK = 2.0;

    /**
     * @var callable|null fn(string $path): bool
     */
    private static $pathExistsResolver = null;

    /**
     * @var callable|null fn(string $middlewareName, string $path, array $server): ?bool
     */
    private static $middlewareDecisionResolver = null;

    /**
     * @var array<string, mixed>
     */
    private static array $lastTrainingTelemetry = [];
    private static bool $rateLimiterConfigured = false;

    /**
     * Register a framework-specific path resolver used during training parity.
     * Pass null to reset to default behavior.
     */
    public static function setPathExistsResolver(?callable $resolver): void
    {
        self::$pathExistsResolver = $resolver;
    }

    /**
     * Register framework/runtime-specific middleware gating logic.
     *
     * Resolver signature:
     *   fn(string $middlewareName, string $path, array $server): ?bool
     * Return true/false to override default decision, or null to fall back.
     */
    public static function setMiddlewareDecisionResolver(?callable $resolver): void
    {
        self::$middlewareDecisionResolver = $resolver;
    }

    /**
     * @return array<string, mixed>
     */
    public static function getLastTrainingTelemetry(): array
    {
        return self::$lastTrainingTelemetry;
    }

    public static function protect()
    {
        $runtimeConfig = Config::toRuntimeConfig();
        self::configureRateLimiter($runtimeConfig);
        $ip = Utils::getClientIp();
        $path = Utils::getRequestPath();

        $headerValidationEnabled = (bool) $runtimeConfig->get('header_validation.enabled', true);
        $ipKeywordBlockEnabled = (bool) $runtimeConfig->get('ip_keyword_block.enabled', true);
        $rateLimitingEnabled = (bool) $runtimeConfig->get('rate_limiting.enabled', true);
        $honeypotEnabled = (bool) $runtimeConfig->get('honeypot.enabled', true);
        $uuidTamperEnabled = (bool) $runtimeConfig->get('uuid_tamper.enabled', true);
        $aiAnomalyEnabled = (bool) $runtimeConfig->get('ai_anomaly.enabled', true);
        $geoBlockEnabled = (bool) $runtimeConfig->get('geo_block.enabled', false);

        if (Utils::isExemptPath($path, $runtimeConfig->get('exempt_paths', Config::$exemptPaths))) {
            return;
        }

        $ipExempt = self::isIpExempt($ip, $runtimeConfig);

        if ($headerValidationEnabled && self::shouldApplyMiddlewareForPath($path, 'header_validation', $runtimeConfig)) {
            $headerValidationOptions = [
                'trust_legitimate_bots' => (bool) $runtimeConfig->get('header_validation.trust_legitimate_bots', false),
                'custom_suspicious_patterns' => (array) $runtimeConfig->get('header_validation.custom_suspicious_patterns', []),
                'custom_legitimate_patterns' => (array) $runtimeConfig->get('header_validation.custom_legitimate_patterns', []),
            ];

            $headerIssue = HeaderValidation::validate(
                $_SERVER,
                $runtimeConfig->get('required_headers', Config::REQUIRED_HEADERS),
                (int) $runtimeConfig->get('header_validation.quality_threshold', (int) $runtimeConfig->get('header_min_score', Config::HEADER_MIN_SCORE)),
                (string) ($_SERVER['REQUEST_METHOD'] ?? ''),
                $headerValidationOptions
            );
            if ($headerIssue !== null) {
                if ($ipExempt) {
                    Utils::log("Suspicious header profile detected but exempt IP skipped blocking: $ip ($headerIssue)");
                }

                if ((bool) $runtimeConfig->get('header_validation.block_suspicious', true)) {
                    if (!$ipExempt) {
                        IPBlocker::blockIp($ip);
                        Utils::log("Suspicious header profile blocked: $ip ($headerIssue)");
                        http_response_code(403);
                        exit;
                    }
                }

                Utils::log("Suspicious header profile detected (block disabled): $ip ($headerIssue)");
            }
        }

        if (!$ipExempt && $ipKeywordBlockEnabled && self::shouldApplyMiddlewareForPath($path, 'ip_keyword_block', $runtimeConfig)) {
            if (IPBlocker::isBlocked($ip)) {
                Utils::log("Blocked IP tried to access: $ip");
                http_response_code(403);
                exit;
            }
        }

        if (!$ipExempt && $geoBlockEnabled && self::shouldApplyMiddlewareForPath($path, 'geo_block', $runtimeConfig)) {
            $countryCode = GeoIP::lookupCountry($ip);
            if ($countryCode !== null && $countryCode !== '') {
                $countryCode = strtoupper($countryCode);
                $allowCountries = array_values(array_map('strtoupper', (array) $runtimeConfig->get('geo_block.allow_countries', [])));
                $blockCountries = array_values(array_map('strtoupper', (array) $runtimeConfig->get('geo_block.block_countries', [])));

                if ($allowCountries !== [] && !in_array($countryCode, $allowCountries, true)) {
                    IPBlocker::blockIp($ip, 'Geo blocked (not in allowlist: ' . $countryCode . ')');
                    http_response_code(403);
                    exit;
                }

                if ($blockCountries !== [] && in_array($countryCode, $blockCountries, true)) {
                    IPBlocker::blockIp($ip, 'Geo blocked (blocked country: ' . $countryCode . ')');
                    http_response_code(403);
                    exit;
                }
            }
        }

        $featureVector = self::extractRequestFeatures();
        $iso = new IsolationForest();
        $modelPath = dirname(__DIR__) . '/resources/forest_model.json';
        $disableAi = filter_var(getenv('AIWAF_DISABLE_AI'), FILTER_VALIDATE_BOOLEAN);
        $anomalyThreshold = (float) $runtimeConfig->get('ai_anomaly_threshold', Config::$aiAnomalyThreshold);

        if (!$ipExempt && $aiAnomalyEnabled && self::shouldApplyMiddlewareForPath($path, 'ai_anomaly', $runtimeConfig) && !$disableAi && file_exists($modelPath) && self::hasMinimumAiLogLines(self::HARD_MIN_AI_LOG_LINES)) {
            $iso->loadModel($modelPath);
            $score = $iso->scoreSamples([$featureVector])[0];

            if ($score > $anomalyThreshold) {
                if (self::shouldBlockAfterAnomalyPrediction($featureVector)) {
                    IPBlocker::blockIp($ip);
                    Utils::log("Anomaly detected and blocked: $ip with score $score");
                    http_response_code(403);
                    exit;
                }

                Utils::log("Anomaly score exceeded threshold but runtime guard skipped blocking: $ip with score $score");
            }
        }

        if (!$ipExempt && $rateLimitingEnabled && self::shouldApplyMiddlewareForPath($path, 'rate_limit', $runtimeConfig)) {
            $maxRequests = (int) $runtimeConfig->get('rate_limiting.max_requests', Config::$rateLimitPerMinute);
            $windowSeconds = (int) $runtimeConfig->get('rate_limiting.window_seconds', 60);
            if (RateLimiter::check($ip, $maxRequests, $windowSeconds)) {
                IPBlocker::blockIp($ip);
                http_response_code(429);
                exit;
            }
        }

        if (!$ipExempt && $ipKeywordBlockEnabled && self::shouldApplyMiddlewareForPath($path, 'ip_keyword_block', $runtimeConfig)) {
            if (DynamicKeywordManager::detect($path) >= Config::$keywordDetectionThreshold) {
                IPBlocker::blockIp($ip);
                http_response_code(403);
                exit;
            }
        }

        if (!$ipExempt && $uuidTamperEnabled && self::shouldApplyMiddlewareForPath($path, 'uuid_tamper', $runtimeConfig)) {
            if (UUIDTamperProtector::isSuspicious($path)) {
                IPBlocker::blockIp($ip);
                http_response_code(403);
                exit;
            }
        }

        if (!$ipExempt && $honeypotEnabled && self::shouldApplyMiddlewareForPath($path, 'honeypot', $runtimeConfig)) {
            if (isset($_POST) && HoneypotChecker::hasTriggered($_POST)) {
                IPBlocker::blockIp($ip);
                http_response_code(403);
                exit;
            }
        }
    }

    private static function configureRateLimiter(RuntimeConfig $runtimeConfig): void
    {
        if (self::$rateLimiterConfigured || RateLimiter::hasDriver()) {
            self::$rateLimiterConfigured = true;
            return;
        }

        $backend = strtolower((string) $runtimeConfig->get('rate_limiting.backend', 'memory'));
        if ($backend === '') {
            $backend = 'memory';
        }

        try {
            if ($backend === 'db') {
                $dbPath = (string) $runtimeConfig->get('rate_limiting.db_path', dirname(__DIR__) . '/resources/rate_limit.sqlite');
                if ($dbPath === '') {
                    $dbPath = dirname(__DIR__) . '/resources/rate_limit.sqlite';
                }
                $dir = dirname($dbPath);
                if (!is_dir($dir)) {
                    mkdir($dir, 0777, true);
                }
                $pdo = new \PDO('sqlite:' . $dbPath);
                $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
                $pdo->exec('CREATE TABLE IF NOT EXISTS ratelimit (ip TEXT NOT NULL, period TEXT NOT NULL, cnt INTEGER NOT NULL, PRIMARY KEY (ip, period))');
                RateLimiter::initAdapter(new DbAdapter($pdo));
                self::$rateLimiterConfigured = true;
                return;
            }

            if ($backend === 'redis') {
                if (!class_exists(\Redis::class)) {
                    Utils::log('Rate limiting backend "redis" requested but ext-redis is unavailable; falling back to memory.');
                } else {
                    $host = (string) $runtimeConfig->get('rate_limiting.redis.host', '127.0.0.1');
                    $port = (int) $runtimeConfig->get('rate_limiting.redis.port', 6379);
                    $timeout = (float) $runtimeConfig->get('rate_limiting.redis.timeout', 1.5);
                    $password = $runtimeConfig->get('rate_limiting.redis.password', null);
                    $database = (int) $runtimeConfig->get('rate_limiting.redis.database', 0);

                    $redis = new \Redis();
                    $connected = $redis->connect($host, $port, $timeout);
                    if (!$connected) {
                        throw new \RuntimeException('Unable to connect to Redis for rate limiting.');
                    }
                    if (is_string($password) && $password !== '') {
                        $redis->auth($password);
                    }
                    if ($database > 0) {
                        $redis->select($database);
                    }
                    RateLimiter::initAdapter(new RedisAdapter($redis));
                    self::$rateLimiterConfigured = true;
                    return;
                }
            }

            if ($backend === 'apcu') {
                if (!function_exists('apcu_enabled') || !apcu_enabled()) {
                    Utils::log('Rate limiting backend "apcu" requested but APCu is unavailable/disabled; falling back to memory.');
                } else {
                    RateLimiter::initAdapter(new ApcuAdapter());
                    self::$rateLimiterConfigured = true;
                    return;
                }
            }
        } catch (\Throwable $e) {
            Utils::log('Rate limiting backend init failed (' . $backend . '): ' . $e->getMessage() . '. Falling back to memory.');
        }

        RateLimiter::initAdapter(new InMemoryAdapter());
        self::$rateLimiterConfigured = true;
    }

    private static function extractRequestFeatures(): array
    {
        $path = Utils::getRequestPath();
        $status = isset($_SERVER['REDIRECT_STATUS']) ? (int) $_SERVER['REDIRECT_STATUS'] : 200;

        $features = [
            strlen($path),
            DynamicKeywordManager::detect($path),
            0.5,
            in_array($status, [404, 500], true) ? 1 : 0,
            0,
            0,
            isset($_POST['aiwaf_honeytrap']) ? 1 : 0,
            UUIDTamperProtector::isSuspicious($path) ? 1 : 0,
        ];
        return $features;
    }

    private static function hasMinimumAiLogLines(int $required): bool
    {
        $featureLogPath = getenv('AIWAF_FEATURE_LOG');
        if (!is_string($featureLogPath) || trim($featureLogPath) === '') {
            $featureLogPath = Config::FEATURE_LOG;
        }

        if (!is_file($featureLogPath)) {
            return false;
        }

        $handle = @fopen($featureLogPath, 'rb');
        if ($handle === false) {
            return false;
        }

        $count = 0;
        while (!feof($handle) && $count < $required) {
            $line = fgets($handle);
            if ($line === false) {
                continue;
            }
            if (trim($line) === '') {
                continue;
            }
            $count++;
        }
        fclose($handle);

        return $count >= $required;
    }

    /**
     * Runtime post-prediction guard: require at least one strong suspicious signal
     * before blocking purely on AI anomaly score.
     *
     * @param array<int, float|int> $featureVector
     */
    private static function shouldBlockAfterAnomalyPrediction(array $featureVector): bool
    {
        $keywordHits = (float) ($featureVector[1] ?? 0.0);
        $statusSignal = (int) ($featureVector[3] ?? 0);
        $honeypotSignal = (int) ($featureVector[6] ?? 0);
        $uuidSignal = (int) ($featureVector[7] ?? 0);

        if ($honeypotSignal === 1 || $uuidSignal === 1 || $statusSignal === 1) {
            return true;
        }

        return $keywordHits >= self::RUNTIME_MIN_KW_HITS_FOR_AI_BLOCK;
    }

    private static function shouldApplyMiddlewareForPath(string $path, string $middlewareName, RuntimeConfig $runtimeConfig): bool
    {
        if (self::$middlewareDecisionResolver !== null) {
            try {
                $decision = call_user_func(self::$middlewareDecisionResolver, $middlewareName, $path, $_SERVER);
                if (is_bool($decision)) {
                    return $decision;
                }
            } catch (\Throwable $e) {
                // Fall through to path-rules behavior if resolver fails.
            }
        }

        $rules = $runtimeConfig->get('path_rules', []);
        if (!is_array($rules) || $rules === []) {
            return true;
        }

        $target = strtolower(trim($middlewareName));
        foreach ($rules as $rule) {
            if (!is_array($rule)) {
                continue;
            }

            $pattern = $rule['PATH'] ?? $rule['path'] ?? null;
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            if (!Exemptions::isPathExempt($path, [$pattern], true, true)) {
                continue;
            }

            $disable = $rule['DISABLE'] ?? $rule['disable'] ?? [];
            if (!is_array($disable)) {
                return true;
            }

            $normalized = array_map(static function ($name): string {
                return strtolower(trim((string) $name));
            }, $disable);

            if (in_array($target, $normalized, true)) {
                return false;
            }

            return true;
        }

        return true;
    }

    private static function isIpExempt(string $ip, RuntimeConfig $runtimeConfig): bool
    {
        if (!RuntimeUtils::isValidIp($ip)) {
            return false;
        }

        $exemptIps = (array) $runtimeConfig->get('rate_limiting.exempt_ips', []);
        foreach ($exemptIps as $pattern) {
            if (self::matchesIpPattern($ip, (string) $pattern)) {
                return true;
            }
        }

        if ((bool) $runtimeConfig->get('exemptions.private_ips_exempted', true) && RuntimeUtils::isPrivateIp($ip)) {
            return true;
        }

        if ((bool) $runtimeConfig->get('exemptions.localhost_exempted', true) && ($ip === '127.0.0.1' || $ip === '::1')) {
            return true;
        }

        $autoPatterns = (array) $runtimeConfig->get('exemptions.auto_exempt_patterns', []);
        foreach ($autoPatterns as $pattern) {
            if (self::matchesIpPattern($ip, (string) $pattern)) {
                return true;
            }
        }

        return false;
    }

    private static function matchesIpPattern(string $ip, string $pattern): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '') {
            return false;
        }

        if ($pattern === $ip) {
            return true;
        }

        if (strpos($pattern, '*') !== false) {
            return fnmatch($pattern, $ip);
        }

        if (strpos($pattern, '/') !== false) {
            return self::ipInCidr($ip, $pattern);
        }

        return false;
    }

    private static function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }

        [$subnet, $maskRaw] = $parts;
        if (!is_numeric($maskRaw)) {
            return false;
        }
        $mask = (int) $maskRaw;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $byteCount = intdiv($mask, 8);
        $bitRemainder = $mask % 8;

        if ($byteCount > 0 && substr($ipBin, 0, $byteCount) !== substr($subnetBin, 0, $byteCount)) {
            return false;
        }

        if ($bitRemainder === 0) {
            return true;
        }

        $maskByte = (0xFF << (8 - $bitRemainder)) & 0xFF;
        $ipByte = ord($ipBin[$byteCount]) & $maskByte;
        $subnetByte = ord($subnetBin[$byteCount]) & $maskByte;

        return $ipByte === $subnetByte;
    }

    /**
     * Train dynamic keyword store and anomaly model from rotated access logs.
     */
    public function detectAndTrain(bool $disableAi = false, bool $forceAi = false): void
    {
        $telemetry = [
            'lines_total' => 0,
            'parsed_rows' => 0,
            'parse_failures' => 0,
            'feature_rows' => 0,
            'known_paths_count' => 0,
            'keyword_candidates' => 0,
            'keywords_learned' => 0,
            'keyword_exempt_skips' => 0,
            'keyword_known_path_skips' => 0,
            'keyword_status_skips' => 0,
            'anomalous_ips' => 0,
            'blocked_ips' => 0,
            'anomalous_country_top' => [],
            'blocked_country_top' => [],
        ];

        $logPath = getenv('AIWAF_ACCESS_LOG');
        if (!is_string($logPath) || trim($logPath) === '') {
            Utils::log('Training skipped: AIWAF_ACCESS_LOG is not configured.');
            self::recordTrainingTelemetry($telemetry, 'skipped-no-log-path');
            return;
        }

        $lines = Logs::readRotatedLogs($logPath);
        $telemetry['lines_total'] = count($lines);
        if ($lines === []) {
            Utils::log('Training skipped: no access logs found.');
            self::recordTrainingTelemetry($telemetry, 'skipped-no-lines');
            return;
        }

        $parsed = [];
        $ip404 = [];
        $ipTimes = [];

        foreach ($lines as $line) {
            $record = Logs::parseLogLine($line);
            if ($record === null) {
                $telemetry['parse_failures'] = (int) $telemetry['parse_failures'] + 1;
                continue;
            }

            $parsed[] = $record;
            $ip = (string) ($record['ip'] ?? '');
            if (!isset($ipTimes[$ip])) {
                $ipTimes[$ip] = [];
            }

            $timestamp = $record['timestamp'] ?? new \DateTime();
            if ($timestamp instanceof \DateTimeInterface) {
                $ipTimes[$ip][] = (float) $timestamp->format('U.u');
            } else {
                $ipTimes[$ip][] = (float) $timestamp;
            }

            if ((string) ($record['status'] ?? '') === '404') {
                $ip404[$ip] = (int) ($ip404[$ip] ?? 0) + 1;
            }
        }

        if ($parsed === []) {
            Utils::log('Training skipped: no parseable log rows.');
            self::recordTrainingTelemetry($telemetry, 'skipped-no-parseable-rows');
            return;
        }

        $telemetry['parsed_rows'] = count($parsed);

        $minTrainLogsRaw = getenv('AIWAF_MIN_TRAIN_LOGS');
        $minTrainLogs = $minTrainLogsRaw === false ? 50 : max(1, (int) $minTrainLogsRaw);
        if (count($parsed) < $minTrainLogs) {
            Utils::log('Training skipped: insufficient parsed logs.');
            self::recordTrainingTelemetry($telemetry, 'skipped-below-min-train-logs');
            return;
        }

        $runtimeConfig = Config::toRuntimeConfig();
        $knownPaths = (array) $runtimeConfig->get('known_paths', Config::$knownPaths);
        $knownPaths = array_values(array_unique(array_merge($knownPaths, self::knownPathsFromEnv())));
        $telemetry['known_paths_count'] = count($knownPaths);

        $records = FeatureExtractor::buildRecords(
            $parsed,
            $ip404,
            static function (string $path) use ($knownPaths): bool {
                return self::pathExists($path, $knownPaths);
            },
            static function (string $path) use ($runtimeConfig): bool {
                return Utils::isExemptPath($path, (array) $runtimeConfig->get('exempt_paths', Config::$exemptPaths));
            },
            Constants::STATUS_IDX
        );

        $staticKw = ['.env', '.git', '.bak', 'conflg', 'shell', 'filemanager'];
        $pythonBatchRaw = getenv('AIWAF_PYTHON_FEATURE_BATCH_SIZE');
        $pythonBatchSize = $pythonBatchRaw === false ? 2000 : max(1, (int) $pythonBatchRaw);
        $pythonChunkRaw = getenv('AIWAF_PYTHON_PARALLEL_CHUNK_SIZE');
        $pythonChunkSize = $pythonChunkRaw === false ? $pythonBatchSize : max(1, (int) $pythonChunkRaw);
        $pythonWorkersRaw = getenv('AIWAF_PYTHON_PARALLEL_WORKERS');
        $pythonWorkers = $pythonWorkersRaw === false
            ? max(1, min((int) (getenv('NUMBER_OF_PROCESSORS') ?: 1), 32))
            : max(1, (int) $pythonWorkersRaw);

        $features = FeatureExtractor::pythonFeaturesBatched(
            $records,
            $ipTimes,
            $staticKw,
            $pythonBatchSize,
            true,
            $pythonChunkSize,
            $pythonWorkers
        );

        $telemetry['feature_rows'] = count($features);

        $keywordTelemetry = $this->learnSuspiciousKeywords(
            $parsed,
            $staticKw,
            (array) $runtimeConfig->get('exempt_paths', Config::$exemptPaths),
            static function (string $path) use ($knownPaths): bool {
                return self::pathExists($path, $knownPaths);
            }
        );
        $telemetry['keyword_candidates'] = (int) ($keywordTelemetry['candidates'] ?? 0);
        $telemetry['keywords_learned'] = (int) ($keywordTelemetry['learned'] ?? 0);
        $telemetry['keyword_exempt_skips'] = (int) ($keywordTelemetry['exempt_skips'] ?? 0);
        $telemetry['keyword_known_path_skips'] = (int) ($keywordTelemetry['known_path_skips'] ?? 0);
        $telemetry['keyword_status_skips'] = (int) ($keywordTelemetry['status_skips'] ?? 0);

        $hardMinAiLogs = self::HARD_MIN_AI_LOG_LINES;
        if (count($parsed) < $hardMinAiLogs) {
            self::recordTrainingTelemetry($telemetry, 'completed-keyword-only-hard-min-ai-logs');
            return;
        }

        $minAiLogsRaw = getenv('AIWAF_MIN_AI_LOGS');
        $minAiLogsConfigured = $minAiLogsRaw === false ? $hardMinAiLogs : max(1, (int) $minAiLogsRaw);
        $minAiLogs = max($hardMinAiLogs, $minAiLogsConfigured);
        $forceAi = $forceAi || filter_var(getenv('AIWAF_FORCE_AI_TRAINING'), FILTER_VALIDATE_BOOLEAN);
        if ($disableAi || (!$forceAi && count($parsed) < $minAiLogs) || $features === []) {
            self::recordTrainingTelemetry($telemetry, 'completed-keyword-only');
            return;
        }

        $matrix = [];
        foreach ($features as $row) {
            $matrix[] = [
                (float) ($row['path_len'] ?? 0),
                (float) ($row['kw_hits'] ?? 0),
                (float) ($row['resp_time'] ?? 0),
                (float) ($row['status_idx'] ?? -1),
                (float) ($row['burst_count'] ?? 0),
                (float) ($row['total_404'] ?? 0),
            ];
        }

        if ($matrix === []) {
            self::recordTrainingTelemetry($telemetry, 'completed-empty-matrix');
            return;
        }

        $forest = new IsolationForest(200, 32);
        $forest->fit($matrix);
        $modelPath = dirname(__DIR__) . '/resources/forest_model.json';
        $forest->saveModel($modelPath);

        $thresholdRaw = getenv('AIWAF_AI_ANOMALY_THRESHOLD');
        if ($thresholdRaw !== false && is_numeric((string) $thresholdRaw)) {
            $anomalyThreshold = (float) $thresholdRaw;
        } else {
            $anomalyThreshold = (float) $runtimeConfig->get('ai_anomaly_threshold', Config::$aiAnomalyThreshold);
        }

        $predictions = $forest->predict($matrix, $anomalyThreshold);

        $anomalousIps = [];
        $statsByIp = [];
        foreach ($predictions as $idx => $pred) {
            if ($pred !== -1) {
                continue;
            }

            $ip = (string) ($features[$idx]['ip'] ?? '');
            if ($ip === '') {
                continue;
            }

            $anomalousIps[$ip] = true;
            if (!isset($statsByIp[$ip])) {
                $statsByIp[$ip] = [
                    'kw_hits_total' => 0.0,
                    'max_404' => 0.0,
                    'burst_total' => 0.0,
                    'requests' => 0,
                ];
            }

            $statsByIp[$ip]['kw_hits_total'] += (float) ($features[$idx]['kw_hits'] ?? 0);
            $statsByIp[$ip]['max_404'] = max($statsByIp[$ip]['max_404'], (float) ($features[$idx]['total_404'] ?? 0));
            $statsByIp[$ip]['burst_total'] += (float) ($features[$idx]['burst_count'] ?? 0);
            $statsByIp[$ip]['requests']++;
        }

        $telemetry['anomalous_ips'] = count($anomalousIps);
        $telemetry['anomalous_country_top'] = self::countryTop(array_keys($anomalousIps));

        $blockedIps = [];
        foreach ($statsByIp as $ip => $stats) {
            $requests = max(1, (int) $stats['requests']);
            $avgKwHits = (float) $stats['kw_hits_total'] / $requests;
            $avgBurst = (float) $stats['burst_total'] / $requests;
            $max404 = (float) $stats['max_404'];

            // Keep burst-only traffic with no suspicious keyword/404 footprint unblocked.
            if ($max404 == 0.0 && $avgKwHits == 0.0) {
                continue;
            }

            // Conservative threshold to avoid blocking normal users with mild anomalies.
            if ($avgKwHits < 2.0 && $max404 < 10.0 && $avgBurst < 15.0 && $requests < 100) {
                continue;
            }

            IPBlocker::blockIp((string) $ip);
            $blockedIps[] = (string) $ip;
        }

        $telemetry['blocked_ips'] = count($blockedIps);
        $telemetry['blocked_country_top'] = self::countryTop($blockedIps);
        self::recordTrainingTelemetry($telemetry, 'completed-ai');
    }

    /**
     * @param array<int, array<string, mixed>> $parsed
     * @param array<int, string> $staticKw
     * @param array<int, string> $exemptPaths
     * @param callable|null $pathExistsFn fn(string $path): bool
     * @return array<string, int>
     */
    private function learnSuspiciousKeywords(array $parsed, array $staticKw, array $exemptPaths, ?callable $pathExistsFn = null): array
    {
        $legitimate = array_flip(TrainingLogic::getDefaultLegitimateKeywords());
        $staticLookup = [];
        foreach ($staticKw as $kw) {
            $staticLookup[strtolower($kw)] = true;
        }

        $telemetry = [
            'candidates' => 0,
            'learned' => 0,
            'exempt_skips' => 0,
            'known_path_skips' => 0,
            'status_skips' => 0,
        ];

        $tokenCounts = [];
        foreach ($parsed as $record) {
            $status = (string) ($record['status'] ?? '');
            if ($status === '' || ($status[0] !== '4' && $status[0] !== '5')) {
                $telemetry['status_skips']++;
                continue;
            }

            $path = (string) ($record['path'] ?? '');
            if (Utils::isExemptPath($path, $exemptPaths)) {
                $telemetry['exempt_skips']++;
                continue;
            }

            if ($pathExistsFn !== null) {
                try {
                    if ((bool) $pathExistsFn($path)) {
                        $telemetry['known_path_skips']++;
                        continue;
                    }
                } catch (\Throwable $e) {
                    // Preserve permissive fallback behavior if path resolver fails.
                }
            }

            $segments = preg_split('/\W+/', strtolower($path), -1, PREG_SPLIT_NO_EMPTY);
            if ($segments === false) {
                continue;
            }

            foreach ($segments as $segment) {
                if (strlen($segment) < 4) {
                    continue;
                }
                if (isset($staticLookup[$segment]) || isset($legitimate[$segment])) {
                    continue;
                }
                if (!TrainingLogic::isMaliciousContext($path, $segment, $status, $staticKw, $pathExistsFn)) {
                    continue;
                }

                $tokenCounts[$segment] = (int) ($tokenCounts[$segment] ?? 0) + 1;
            }
        }

        $telemetry['candidates'] = count($tokenCounts);

        if ($tokenCounts === []) {
            return $telemetry;
        }

        arsort($tokenCounts);
        $toLearn = [];
        $i = 0;
        foreach ($tokenCounts as $token => $count) {
            if ($count < 2) {
                continue;
            }
            $toLearn[] = $token;
            $i++;
            if ($i >= 10) {
                break;
            }
        }

        if ($toLearn !== []) {
            DynamicKeywordManager::addKeywords($toLearn);
        }

        $telemetry['learned'] = count($toLearn);
        return $telemetry;
    }

    /**
     * @param array<int, string> $knownPaths
     */
    private static function pathExists(string $path, array $knownPaths): bool
    {
        if (self::$pathExistsResolver !== null) {
            try {
                return (bool) call_user_func(self::$pathExistsResolver, $path);
            } catch (\Throwable $e) {
                // Fallback to known-path matching if resolver fails.
            }
        }

        $candidate = self::normalizePath($path);
        if ($candidate === '') {
            return false;
        }

        foreach ($knownPaths as $knownPath) {
            $known = self::normalizePath((string) $knownPath);
            if ($known === '') {
                continue;
            }

            if ($candidate === $known) {
                return true;
            }

            if (strpos($candidate, $known . '/') === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private static function knownPathsFromEnv(): array
    {
        $raw = getenv('AIWAF_KNOWN_PATHS');
        if ($raw === false) {
            return [];
        }

        $parts = array_map('trim', explode(',', (string) $raw));
        return array_values(array_filter($parts, static function (string $part): bool {
            return $part !== '';
        }));
    }

    private static function normalizePath(string $path): string
    {
        $parsed = parse_url($path, PHP_URL_PATH);
        $base = is_string($parsed) ? $parsed : $path;
        $normalized = '/' . trim($base, '/');
        return $normalized === '/' ? '/' : rtrim($normalized, '/');
    }

    /**
     * @param array<int, string> $ips
     * @return array<int, array{country:string,count:int}>
     */
    private static function countryTop(array $ips): array
    {
        $counts = [];
        foreach ($ips as $ip) {
            $code = GeoIP::lookupCountry((string) $ip);
            if ($code === null || $code === '') {
                $code = 'UNKNOWN';
            }
            $counts[$code] = (int) ($counts[$code] ?? 0) + 1;
        }

        arsort($counts);
        $top = [];
        $i = 0;
        foreach ($counts as $country => $count) {
            $top[] = ['country' => (string) $country, 'count' => (int) $count];
            $i++;
            if ($i >= 10) {
                break;
            }
        }
        return $top;
    }

    /**
     * @param array<string, mixed> $telemetry
     */
    private static function recordTrainingTelemetry(array $telemetry, string $status): void
    {
        $telemetry['status'] = $status;
        $telemetry['at'] = date(DATE_ATOM);
        self::$lastTrainingTelemetry = $telemetry;

        $json = json_encode($telemetry);
        if ($json !== false) {
            Utils::log('Trainer telemetry: ' . $json);
        }
    }
}
