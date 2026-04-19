<?php
namespace AIWAF;

class HoneypotChecker
{
    public static function hasTriggered(array $postData): bool
    {
        return !empty($postData['aiwaf_honeytrap']);
    }
}
