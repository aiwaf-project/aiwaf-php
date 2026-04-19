<?php

declare(strict_types=1);

use AIWAF\AIWAF;
use AIWAF\Core\HeaderValidation;
use AIWAF\Core\RuntimeConfig;
use AIWAF\Core\RuntimeUtils;
use AIWAF\FeatureExtractor;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestCoreParity extends TestCase
{
    protected function tearDown(): void
    {
        AIWAF::setMiddlewareDecisionResolver(null);
        AIWAF::setPathExistsResolver(null);
        parent::tearDown();
    }

    public function testHeaderValidationFlagsMissingBrowserHeadersCombination(): void
    {
        $server = [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'HTTP_ACCEPT' => 'text/html',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
        ];

        $issue = HeaderValidation::validate($server, ['HTTP_USER_AGENT', 'HTTP_ACCEPT'], 0);
        $this->assertSame('Suspicious headers: Missing all browser-standard headers', $issue);
    }

    public function testHeaderValidationFlagsModernBrowserWithHttp10(): void
    {
        $server = [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/123.0.0.0',
            'HTTP_ACCEPT' => 'text/html',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'HTTP_ACCEPT_ENCODING' => 'gzip',
            'HTTP_CONNECTION' => 'keep-alive',
            'SERVER_PROTOCOL' => 'HTTP/1.0',
        ];

        $issue = HeaderValidation::validate($server, ['HTTP_USER_AGENT', 'HTTP_ACCEPT'], 3);
        $this->assertSame('Suspicious headers: Modern browser with HTTP/1.0', $issue);
    }

    public function testHeaderValidationResolvesRequiredHeadersByMethod(): void
    {
        $server = [
            'REQUEST_METHOD' => 'GET',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'HTTP_ACCEPT_ENCODING' => 'gzip',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
        ];

        $required = [
            'DEFAULT' => ['HTTP_USER_AGENT', 'HTTP_ACCEPT'],
            'GET' => ['HTTP_USER_AGENT'],
        ];

        $issue = HeaderValidation::validate($server, $required, 0, 'GET');
        $this->assertNull($issue);
    }

    public function testHeaderValidationCustomSuspiciousPatternTriggers(): void
    {
        $server = [
            'HTTP_USER_AGENT' => 'my-bad-bot/1.0',
            'HTTP_ACCEPT' => 'text/html',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'HTTP_ACCEPT_ENCODING' => 'gzip',
            'HTTP_CONNECTION' => 'keep-alive',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
        ];

        $issue = HeaderValidation::validate(
            $server,
            ['HTTP_USER_AGENT', 'HTTP_ACCEPT'],
            0,
            'GET',
            [
                'custom_suspicious_patterns' => ['bad-bot'],
                'trust_legitimate_bots' => false,
            ]
        );

        $this->assertStringContainsString('Suspicious user agent', (string) $issue);
    }

    public function testHeaderValidationCanTrustCustomLegitimateBot(): void
    {
        $server = [
            'HTTP_USER_AGENT' => 'my-monitor-bot/1.0',
            'HTTP_ACCEPT' => 'text/html',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
        ];

        $issue = HeaderValidation::validate(
            $server,
            ['HTTP_USER_AGENT', 'HTTP_ACCEPT'],
            10,
            'GET',
            [
                'trust_legitimate_bots' => true,
                'custom_legitimate_patterns' => ['my-monitor-bot'],
            ]
        );

        $this->assertNull($issue);
    }

    public function testRuntimeUtilsUsesForwardedIpForProxyLikePeer(): void
    {
        $server = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.10, 10.0.0.2',
        ];

        $ip = RuntimeUtils::getIpFromHeaders($server);
        $this->assertSame('198.51.100.10', $ip);
    }

    public function testFeatureExtractorStatusIndexMatchesConstantsOrder(): void
    {
        $features = FeatureExtractor::extractFeatures([
            'path' => '/admin',
            'status' => '404',
            'resp_time' => 0.2,
            'ip' => '1.2.3.4',
        ]);

        $this->assertSame(2, $features['status_idx']);
    }

    public function testFeatureExtractorBurstAndKeywordHitsFromRecord(): void
    {
        $record = [
            'ip' => '1.2.3.4',
            'path_len' => 20,
            'path_lower' => '/wp-admin/config',
            'resp_time' => 0.4,
            'status_idx' => 1,
            'timestamp' => 1000.0,
            'kw_check' => true,
            'total_404' => 3,
        ];

        $features = FeatureExtractor::pythonFeatureFromRecord(
            $record,
            ['1.2.3.4' => [995.0, 990.0, 970.0]],
            ['wp-admin', 'config', '.env']
        );

        $this->assertSame(2, $features['kw_hits']);
        $this->assertSame(2, $features['burst_count']);
    }

    public function testMiddlewareDecisionResolverOverridesPathRules(): void
    {
        AIWAF::setMiddlewareDecisionResolver(static function (string $middlewareName, string $path, array $server): ?bool {
            if ($middlewareName === 'rate_limit' && $path === '/api/orders') {
                return false;
            }

            return null;
        });

        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('shouldApplyMiddlewareForPath');
        $method->setAccessible(true);

        $config = new RuntimeConfig([
            'path_rules' => [
                [
                    'PATH' => '/api/*',
                    'DISABLE' => [],
                ],
            ],
        ], null, false);

        $applies = $method->invoke(null, '/api/orders', 'rate_limit', $config);
        $this->assertFalse((bool) $applies);
    }

    public function testPathRulesCanDisableEachMiddlewareByName(): void
    {
        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('shouldApplyMiddlewareForPath');
        $method->setAccessible(true);

        $middlewares = [
            'header_validation',
            'ip_keyword_block',
            'geo_block',
            'ai_anomaly',
            'rate_limit',
            'uuid_tamper',
            'honeypot',
        ];

        foreach ($middlewares as $middleware) {
            $config = new RuntimeConfig([
                'path_rules' => [
                    [
                        'PATH' => '/api/*',
                        'DISABLE' => [$middleware],
                    ],
                ],
            ], null, false);

            $applies = $method->invoke(null, '/api/orders', $middleware, $config);
            $this->assertFalse((bool) $applies, 'Expected middleware to be disabled: ' . $middleware);
        }
    }

    public function testPathRulesKeepMiddlewareEnabledWhenNotListedInDisable(): void
    {
        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('shouldApplyMiddlewareForPath');
        $method->setAccessible(true);

        $config = new RuntimeConfig([
            'path_rules' => [
                [
                    'PATH' => '/api/*',
                    'DISABLE' => ['rate_limit'],
                ],
            ],
        ], null, false);

        $this->assertTrue((bool) $method->invoke(null, '/api/orders', 'geo_block', $config));
        $this->assertFalse((bool) $method->invoke(null, '/api/orders', 'rate_limit', $config));
    }

    public function testMiddlewareDecisionResolverCanForceGeoBlockEvenWhenRuleDisablesIt(): void
    {
        AIWAF::setMiddlewareDecisionResolver(static function (string $middlewareName, string $path, array $server): ?bool {
            if ($middlewareName === 'geo_block' && $path === '/api/orders') {
                return true;
            }

            return null;
        });

        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('shouldApplyMiddlewareForPath');
        $method->setAccessible(true);

        $config = new RuntimeConfig([
            'path_rules' => [
                [
                    'PATH' => '/api/*',
                    'DISABLE' => ['geo_block'],
                ],
            ],
        ], null, false);

        $applies = $method->invoke(null, '/api/orders', 'geo_block', $config);
        $this->assertTrue((bool) $applies);
    }

    public function testIsIpExemptSupportsExactWildcardAndCidrPatterns(): void
    {
        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('isIpExempt');
        $method->setAccessible(true);

        $config = new RuntimeConfig([
            'rate_limiting' => [
                'exempt_ips' => ['203.0.113.77', '198.51.100.*', '10.0.0.0/24'],
            ],
            'exemptions' => [
                'private_ips_exempted' => false,
                'localhost_exempted' => false,
                'auto_exempt_patterns' => [],
            ],
        ], null, false);

        $this->assertTrue((bool) $method->invoke(null, '203.0.113.77', $config));
        $this->assertTrue((bool) $method->invoke(null, '198.51.100.42', $config));
        $this->assertTrue((bool) $method->invoke(null, '10.0.0.5', $config));
        $this->assertFalse((bool) $method->invoke(null, '203.0.113.10', $config));
    }
}
