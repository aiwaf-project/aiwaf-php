<?php

declare(strict_types=1);

use AIWAF\AIWAF;
use AIWAF\Core\RuntimeConfig;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

class TestMiddlewareIntegrationParity extends TestCase
{
    protected function tearDown(): void
    {
        AIWAF::setMiddlewareDecisionResolver(null);
        parent::tearDown();
    }

    public function testPathRulesAcceptLowercaseKeysAndDisableNamesCaseInsensitive(): void
    {
        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('shouldApplyMiddlewareForPath');
        $method->setAccessible(true);

        $config = new RuntimeConfig([
            'path_rules' => [
                [
                    'path' => '/api/*',
                    'disable' => ['Geo_Block', 'Rate_Limit'],
                ],
            ],
        ], null, false);

        $this->assertFalse((bool) $method->invoke(null, '/api/v1/orders', 'geo_block', $config));
        $this->assertFalse((bool) $method->invoke(null, '/api/v1/orders', 'rate_limit', $config));
        $this->assertTrue((bool) $method->invoke(null, '/api/v1/orders', 'uuid_tamper', $config));
    }

    public function testMiddlewareDecisionResolverExceptionFallsBackToPathRules(): void
    {
        AIWAF::setMiddlewareDecisionResolver(static function (): ?bool {
            throw new RuntimeException('resolver failed');
        });

        $ref = new ReflectionClass(AIWAF::class);
        $method = $ref->getMethod('shouldApplyMiddlewareForPath');
        $method->setAccessible(true);

        $config = new RuntimeConfig([
            'path_rules' => [
                [
                    'PATH' => '/admin/*',
                    'DISABLE' => ['header_validation'],
                ],
            ],
        ], null, false);

        $applies = $method->invoke(null, '/admin/panel', 'header_validation', $config);
        $this->assertFalse((bool) $applies);
    }
}
