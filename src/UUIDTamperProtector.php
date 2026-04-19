<?php
namespace AIWAF;

class UUIDTamperProtector
{
    public static function isSuspicious(string $path): bool
    {
        if (preg_match('/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})/', $path, $matches)) {
            return false;
        }
        return true;
    }
}
