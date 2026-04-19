<?php
// tests/TestDynamicKeywordManager.php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../vendor/autoload.php';

use AIWAF\DynamicKeywordManager;

class TestDynamicKeywordManager extends TestCase
{
    private DynamicKeywordManager $manager;

    protected function setUp(): void
    {
        DynamicKeywordManager::resetKeywords();
        $this->manager = new DynamicKeywordManager();
    }

    public function testAddAndRemoveKeywords(): void
    {
        $added = $this->manager->addKeywords(['testkw']);
        $this->assertTrue($added);
        $this->assertContains('testkw', $this->manager->getKeywords());
        $removed = $this->manager->removeKeywords(['testkw']);
        $this->assertTrue($removed);
        $this->assertNotContains('testkw', $this->manager->getKeywords());
    }
}