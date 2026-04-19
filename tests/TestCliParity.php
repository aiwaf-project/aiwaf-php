<?php

declare(strict_types=1);

use AIWAF\Config;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestCliParity extends TestCase
{
    private array $savedEnv = [];
    private ?string $blockedIpsBackup = null;

    protected function setUp(): void
    {
        $path = Config::BLOCKED_IPS_PATH;
        if (file_exists($path)) {
            $raw = file_get_contents($path);
            $this->blockedIpsBackup = $raw === false ? null : $raw;
        }
    }

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

        $path = Config::BLOCKED_IPS_PATH;
        if ($this->blockedIpsBackup === null) {
            @unlink($path);
        } else {
            $dir = dirname($path);
            if (!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
            file_put_contents($path, $this->blockedIpsBackup);
        }
    }

    public function testSetupScriptCreatesBlockedIpsFile(): void
    {
        @unlink(Config::BLOCKED_IPS_PATH);
        $exit = $this->runPhpScript('setup.php', []);

        $this->assertSame(0, $exit['code']);
        $this->assertFileExists(Config::BLOCKED_IPS_PATH);

        $decoded = json_decode((string) file_get_contents(Config::BLOCKED_IPS_PATH), true);
        $this->assertIsArray($decoded);
    }

    public function testDetectAndTrainCliScriptCompletesWithoutAccessLog(): void
    {
        $this->setEnv('AIWAF_ACCESS_LOG', null);

        $exit = $this->runPhpScript('cli/detect_and_train.php', []);

        $this->assertSame(0, $exit['code']);
        $this->assertStringContainsString('detectAndTrain completed successfully', $exit['stdout']);
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

    /**
     * @return array{code:int,stdout:string,stderr:string}
     */
    private function runPhpScript(string $relativeScript, array $args): array
    {
        $root = dirname(__DIR__);
        $php = PHP_BINARY;
        $script = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativeScript);

        $parts = [escapeshellarg($php), escapeshellarg($script)];
        foreach ($args as $arg) {
            $parts[] = escapeshellarg((string) $arg);
        }

        $command = implode(' ', $parts);
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $proc = proc_open($command, $descriptors, $pipes, $root);
        $this->assertIsResource($proc);

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $code = proc_close($proc);

        return [
            'code' => is_int($code) ? $code : 1,
            'stdout' => is_string($stdout) ? $stdout : '',
            'stderr' => is_string($stderr) ? $stderr : '',
        ];
    }
}
