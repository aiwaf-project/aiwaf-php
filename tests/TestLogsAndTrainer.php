<?php

declare(strict_types=1);

use AIWAF\AIWAF;
use AIWAF\Config;
use AIWAF\Core\Logs;
use AIWAF\DynamicKeywordManager;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestLogsAndTrainer extends TestCase
{
    private array $savedEnv = [];
    private array $fileBackups = [];

    protected function setUp(): void
    {
        $this->backupFile(Config::DYNAMIC_KEYWORDS_PATH);
        $this->backupFile(Config::BLOCKED_IPS_PATH);
        $this->backupFile(dirname(__DIR__) . '/resources/forest_model.json');

        AIWAF::setPathExistsResolver(null);
        DynamicKeywordManager::resetKeywords();
    }

    protected function tearDown(): void
    {
        AIWAF::setPathExistsResolver(null);
        DynamicKeywordManager::resetKeywords();

        foreach ($this->savedEnv as $name => $value) {
            if ($value === false || $value === null) {
                putenv($name);
            } else {
                putenv($name . '=' . $value);
            }
        }
        $this->savedEnv = [];

        foreach ($this->fileBackups as $path => $content) {
            if ($content === null) {
                @unlink($path);
                continue;
            }

            $dir = dirname($path);
            if (!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
            file_put_contents($path, $content);
        }
        $this->fileBackups = [];
    }

    public function testReadRotatedLogsReadsPlainAndGzipFiles(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_logs_' . uniqid('', true);
        mkdir($dir, 0777, true);

        $base = $dir . DIRECTORY_SEPARATOR . 'access.log';
        file_put_contents($base, "base-line\n");
        file_put_contents($base . '.1', "rotated-line\n");

        $gz = gzopen($base . '.2.gz', 'wb9');
        $this->assertNotFalse($gz);
        if (is_resource($gz)) {
            gzwrite($gz, "gz-line\n");
            gzclose($gz);
        }

        $lines = Logs::readRotatedLogs($base);

        $this->assertContains('base-line', $lines);
        $this->assertContains('rotated-line', $lines);
        $this->assertContains('gz-line', $lines);

        @unlink($base);
        @unlink($base . '.1');
        @unlink($base . '.2.gz');
        @rmdir($dir);
    }

    public function testParseLogLineParsesCombinedLogWithResponseTime(): void
    {
        $line = '203.0.113.11 - - [18/Apr/2026:12:00:00 +0000] "GET /wp-admin/config.php HTTP/1.1" 404 123 "-" "UA" response-time=0.321';

        $parsed = Logs::parseLogLine($line);

        $this->assertIsArray($parsed);
        $this->assertSame('203.0.113.11', $parsed['ip']);
        $this->assertSame('/wp-admin/config.php', $parsed['path']);
        $this->assertSame('404', $parsed['status']);
        $this->assertSame(0.321, $parsed['response_time']);
        $this->assertInstanceOf(\DateTime::class, $parsed['timestamp']);
    }

    public function testParseLogLineParsesStandardCombinedLogWithoutResponseTime(): void
    {
        $line = '203.0.113.44 - - [18/Apr/2026:12:00:05 +0000] "GET /catalog/items HTTP/1.1" 200 567 "https://example.test" "UA"';

        $parsed = Logs::parseLogLine($line);

        $this->assertIsArray($parsed);
        $this->assertSame('203.0.113.44', $parsed['ip']);
        $this->assertSame('/catalog/items', $parsed['path']);
        $this->assertSame('200', $parsed['status']);
        $this->assertSame(0.0, $parsed['response_time']);
    }

    public function testParseLogLineParsesIpv6SourceAddress(): void
    {
        $line = '2001:db8::10 - - [18/Apr/2026:12:00:06 +0000] "GET /ipv6/path HTTP/1.1" 404 42 "-" "UA" response-time=0.051';

        $parsed = Logs::parseLogLine($line);

        $this->assertIsArray($parsed);
        $this->assertSame('2001:db8::10', $parsed['ip']);
        $this->assertSame('/ipv6/path', $parsed['path']);
        $this->assertSame('404', $parsed['status']);
    }

    public function testReadRotatedLogsReadsCsvRowsAsAccessLines(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_csv_logs_' . uniqid('', true);
        mkdir($dir, 0777, true);

        $base = $dir . DIRECTORY_SEPARATOR . 'access.csv';
        file_put_contents(
            $base,
            implode(",", ['timestamp', 'ip', 'method', 'path', 'status_code', 'content_length', 'referer', 'user_agent', 'response_time']) . PHP_EOL .
            implode(",", ['2026-04-18T12:00:10+00:00', '2001:db8::20', 'GET', '/csv/route', '200', '10', '-', 'UA', '0.090']) . PHP_EOL
        );

        $lines = Logs::readRotatedLogs($base);
        $this->assertNotEmpty($lines);

        $parsed = Logs::parseLogLine($lines[0]);
        $this->assertIsArray($parsed);
        $this->assertSame('2001:db8::20', $parsed['ip']);
        $this->assertSame('/csv/route', $parsed['path']);

        @unlink($base);
        @rmdir($dir);
    }

    public function testParseLogLineReturnsNullForMalformedInput(): void
    {
        $this->assertNull(Logs::parseLogLine('this is not an access log line'));
    }

    public function testDetectAndTrainSkipsWhenAccessLogEnvMissing(): void
    {
        $this->setEnv('AIWAF_ACCESS_LOG', null);

        $modelPath = dirname(__DIR__) . '/resources/forest_model.json';
        @unlink($modelPath);

        $waf = new AIWAF();
        $waf->detectAndTrain(false, true);

        $this->assertFileDoesNotExist($modelPath);
        $telemetry = AIWAF::getLastTrainingTelemetry();
        $this->assertSame('skipped-no-log-path', $telemetry['status'] ?? null);
    }

    public function testDetectAndTrainLearnsKeywordsAndSkipsAiBelowHardMinimum(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_train_' . uniqid('', true);
        mkdir($dir, 0777, true);
        $logPath = $dir . DIRECTORY_SEPARATOR . 'access.log';

        $lines = [];
        for ($i = 0; $i < 80; $i++) {
            $sec = str_pad((string) ($i % 60), 2, '0', STR_PAD_LEFT);
            if ($i < 40) {
                $path = '/x/../..//xploittest/config.php?x=union+select';
                $status = '404';
                $ip = '198.51.100.12';
                $rt = '0.250';
            } else {
                $path = '/products/list';
                $status = '200';
                $ip = '198.51.100.90';
                $rt = '0.040';
            }

            $lines[] = sprintf(
                '%s - - [18/Apr/2026:12:00:%s +0000] "GET %s HTTP/1.1" %s 123 "-" "UA" response-time=%s',
                $ip,
                $sec,
                $path,
                $status,
                $rt
            );
        }

        file_put_contents($logPath, implode(PHP_EOL, $lines) . PHP_EOL);

        $this->setEnv('AIWAF_ACCESS_LOG', $logPath);
        $this->setEnv('AIWAF_MIN_TRAIN_LOGS', '1');
        $this->setEnv('AIWAF_MIN_AI_LOGS', '1');
        $this->setEnv('AIWAF_FORCE_AI_TRAINING', 'true');
        $this->setEnv('AIWAF_PYTHON_FEATURE_BATCH_SIZE', '8');
        $this->setEnv('AIWAF_PYTHON_PARALLEL_CHUNK_SIZE', '4');
        $this->setEnv('AIWAF_PYTHON_PARALLEL_WORKERS', '2');

        $waf = new AIWAF();
        $waf->detectAndTrain(false, true);

        $modelPath = dirname(__DIR__) . '/resources/forest_model.json';
        $this->assertFileDoesNotExist($modelPath);

        $keywords = DynamicKeywordManager::getKeywords();
        $this->assertContains('xploittest', $keywords);

        $telemetry = AIWAF::getLastTrainingTelemetry();
        $this->assertSame('completed-keyword-only-hard-min-ai-logs', $telemetry['status'] ?? null);
        $this->assertGreaterThan(0, (int) ($telemetry['parsed_rows'] ?? 0));
        $this->assertGreaterThan(0, (int) ($telemetry['feature_rows'] ?? 0));

        @unlink($logPath);
        @rmdir($dir);
    }

    public function testDetectAndTrainDisableAiStillLearnsKeywords(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_train_no_ai_' . uniqid('', true);
        mkdir($dir, 0777, true);
        $logPath = $dir . DIRECTORY_SEPARATOR . 'access.log';

        $lines = [
            '198.51.100.20 - - [18/Apr/2026:12:01:00 +0000] "GET /x/../..//disableaitest/config.php HTTP/1.1" 404 120 "-" "UA" response-time=0.200',
            '198.51.100.20 - - [18/Apr/2026:12:01:01 +0000] "GET /x/../..//disableaitest/config.php HTTP/1.1" 404 120 "-" "UA" response-time=0.210',
            '198.51.100.21 - - [18/Apr/2026:12:01:02 +0000] "GET /healthy/page HTTP/1.1" 200 120 "-" "UA" response-time=0.030',
        ];
        file_put_contents($logPath, implode(PHP_EOL, $lines) . PHP_EOL);

        $this->setEnv('AIWAF_ACCESS_LOG', $logPath);
        $this->setEnv('AIWAF_MIN_TRAIN_LOGS', '1');
        $this->setEnv('AIWAF_MIN_AI_LOGS', '1');

        $modelPath = dirname(__DIR__) . '/resources/forest_model.json';
        @unlink($modelPath);

        $waf = new AIWAF();
        $waf->detectAndTrain(true, true);

        $this->assertFileDoesNotExist($modelPath);
        $keywords = DynamicKeywordManager::getKeywords();
        $this->assertContains('disableaitest', $keywords);

        $telemetry = AIWAF::getLastTrainingTelemetry();
        $this->assertSame('completed-keyword-only-hard-min-ai-logs', $telemetry['status'] ?? null);

        @unlink($logPath);
        @rmdir($dir);
    }

    public function testDetectAndTrainSkipsWhenBelowMinimumTrainLogs(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_train_min_' . uniqid('', true);
        mkdir($dir, 0777, true);
        $logPath = $dir . DIRECTORY_SEPARATOR . 'access.log';

        file_put_contents(
            $logPath,
            '198.51.100.30 - - [18/Apr/2026:12:02:00 +0000] "GET /x/../..//minlogtest/config.php HTTP/1.1" 404 100 "-" "UA" response-time=0.100' . PHP_EOL
        );

        $this->setEnv('AIWAF_ACCESS_LOG', $logPath);
        $this->setEnv('AIWAF_MIN_TRAIN_LOGS', '5');
        $this->setEnv('AIWAF_MIN_AI_LOGS', '1');
        $this->setEnv('AIWAF_FORCE_AI_TRAINING', 'true');

        $modelPath = dirname(__DIR__) . '/resources/forest_model.json';
        @unlink($modelPath);

        $waf = new AIWAF();
        $waf->detectAndTrain(false, true);

        $this->assertFileDoesNotExist($modelPath);
        $keywords = DynamicKeywordManager::getKeywords();
        $this->assertNotContains('minlogtest', $keywords);

        @unlink($logPath);
        @rmdir($dir);
    }

    public function testDetectAndTrainPathResolverPreventsLearningKnownRoutes(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_train_route_resolver_' . uniqid('', true);
        mkdir($dir, 0777, true);
        $logPath = $dir . DIRECTORY_SEPARATOR . 'access.log';

        $targetPath = '/tenant/adminportal/reports/config.php';
        $lines = [
            '198.51.100.40 - - [18/Apr/2026:12:03:00 +0000] "GET ' . $targetPath . ' HTTP/1.1" 404 100 "-" "UA" response-time=0.100',
            '198.51.100.40 - - [18/Apr/2026:12:03:01 +0000] "GET ' . $targetPath . ' HTTP/1.1" 404 100 "-" "UA" response-time=0.120',
        ];
        file_put_contents($logPath, implode(PHP_EOL, $lines) . PHP_EOL);

        $this->setEnv('AIWAF_ACCESS_LOG', $logPath);
        $this->setEnv('AIWAF_MIN_TRAIN_LOGS', '1');

        AIWAF::setPathExistsResolver(static function (string $path): bool {
            return strpos($path, '/tenant/adminportal/reports') === 0;
        });

        $waf = new AIWAF();
        $waf->detectAndTrain(true, true);

        $keywords = DynamicKeywordManager::getKeywords();
        $this->assertNotContains('adminportal', $keywords);
        $this->assertNotContains('reports', $keywords);

        @unlink($logPath);
        @rmdir($dir);
    }

    public function testDetectAndTrainKnownPathsEnvPreventsLearning(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'aiwaf_train_known_paths_' . uniqid('', true);
        mkdir($dir, 0777, true);
        $logPath = $dir . DIRECTORY_SEPARATOR . 'access.log';

        $targetPath = '/known/route/subpath/manage.php';
        $lines = [
            '198.51.100.41 - - [18/Apr/2026:12:04:00 +0000] "GET ' . $targetPath . ' HTTP/1.1" 404 100 "-" "UA" response-time=0.100',
            '198.51.100.41 - - [18/Apr/2026:12:04:01 +0000] "GET ' . $targetPath . ' HTTP/1.1" 404 100 "-" "UA" response-time=0.110',
        ];
        file_put_contents($logPath, implode(PHP_EOL, $lines) . PHP_EOL);

        $this->setEnv('AIWAF_ACCESS_LOG', $logPath);
        $this->setEnv('AIWAF_MIN_TRAIN_LOGS', '1');
        $this->setEnv('AIWAF_KNOWN_PATHS', '/known/route');

        $waf = new AIWAF();
        $waf->detectAndTrain(true, true);

        $keywords = DynamicKeywordManager::getKeywords();
        $this->assertNotContains('subpath', $keywords);
        $this->assertNotContains('manage', $keywords);

        @unlink($logPath);
        @rmdir($dir);
    }

    private function backupFile(string $path): void
    {
        if (array_key_exists($path, $this->fileBackups)) {
            return;
        }

        if (file_exists($path)) {
            $this->fileBackups[$path] = file_get_contents($path);
        } else {
            $this->fileBackups[$path] = null;
        }
    }

    private function setEnv(string $name, ?string $value): void
    {
        if (!array_key_exists($name, $this->savedEnv)) {
            $this->savedEnv[$name] = getenv($name);
        }

        if ($value === null) {
            putenv($name);
            return;
        }

        putenv($name . '=' . $value);
    }
}
