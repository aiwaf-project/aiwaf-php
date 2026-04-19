<?php
namespace AIWAF\Core;

final class Exemptions
{
    public static function normalizePath(string $path, ?bool $trailingSlash = null): string
    {
        $cleaned = trim($path);
        if ($cleaned === '') {
            return '/';
        }

        $cleaned = preg_replace('#/{2,}#', '/', $cleaned) ?? $cleaned;
        if ($cleaned[0] !== '/') {
            $cleaned = '/' . $cleaned;
        }

        if ($trailingSlash === true && substr($cleaned, -1) !== '/') {
            $cleaned .= '/';
        }
        if ($trailingSlash === false && $cleaned !== '/') {
            $cleaned = rtrim($cleaned, '/');
            if ($cleaned === '') {
                $cleaned = '/';
            }
        }

        return strtolower($cleaned);
    }

    public static function isPathExempt(
        string $path,
        array $exemptPaths,
        bool $allowWildcards = true,
        bool $allowPrefix = true
    ): bool {
        if ($path === '') {
            return false;
        }

        $normalizedPath = self::normalizePath($path, null);

        foreach ($exemptPaths as $exempt) {
            if (!is_string($exempt) || $exempt === '') {
                continue;
            }

            $normalizedExempt = self::normalizePath($exempt, null);

            if ($allowWildcards && strpos($normalizedExempt, '*') !== false) {
                if (fnmatch($normalizedExempt, $normalizedPath)) {
                    return true;
                }
                continue;
            }

            if ($normalizedPath === $normalizedExempt) {
                return true;
            }

            if ($allowPrefix) {
                $prefix = rtrim($normalizedExempt, '/');
                if ($prefix !== '' && ($normalizedPath === $prefix || strpos($normalizedPath, $prefix . '/') === 0)) {
                    return true;
                }
            }
        }

        return false;
    }
}
