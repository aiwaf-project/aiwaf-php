<?php
require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use AIWAF\HoneypotChecker;

class TestHoneypotChecker extends TestCase
{
    public function testCleanPost()
    {
        $postData = [];
        $this->assertFalse(HoneypotChecker::hasTriggered($postData));
    }

    public function testBotDetected()
    {
        $postData = ['aiwaf_honeytrap' => 'gotcha'];
        $this->assertTrue(HoneypotChecker::hasTriggered($postData));
    }
}
