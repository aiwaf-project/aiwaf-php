<?php
namespace AIWAF\Core;

final class RuntimeUtils
{
    public static function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public static function isPrivateIp(string $ip): bool
    {
        if (!self::isValidIp($ip)) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if ($ip === '127.0.0.1') {
                return true;
            }

            if (strpos($ip, '10.') === 0 || strpos($ip, '192.168.') === 0) {
                return true;
            }

            if (preg_match('/^172\.(\d+)\./', $ip, $m) === 1) {
                $octet = (int) ($m[1] ?? -1);
                if ($octet >= 16 && $octet <= 31) {
                    return true;
                }
            }

            if (strpos($ip, '169.254.') === 0) {
                return true;
            }

            return false;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $lower = strtolower($ip);
            if ($lower === '::1') {
                return true;
            }

            if (strpos($lower, 'fe80:') === 0) {
                return true;
            }

            if (strpos($lower, 'fc') === 0 || strpos($lower, 'fd') === 0) {
                return true;
            }
        }

        return false;
    }

    public static function getIpFromHeaders(array $server): string
    {
        $clientIp = isset($server['REMOTE_ADDR']) ? trim((string) $server['REMOTE_ADDR']) : '';
        if ($clientIp !== '' && self::isValidIp($clientIp) && !self::isProxyLikeIp($clientIp)) {
            return $clientIp;
        }

        $headerCandidates = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_X_CLIENT_IP',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_CLIENT_IP',
        ];

        foreach ($headerCandidates as $header) {
            if (!isset($server[$header]) || $server[$header] === '') {
                continue;
            }

            $parts = explode(',', (string) $server[$header]);
            $candidate = trim($parts[0]);
            if (self::isValidIp($candidate)) {
                return $candidate;
            }
        }

        return $clientIp !== '' ? $clientIp : '0.0.0.0';
    }

    public static function isProxyLikeIp(string $ip): bool
    {
        if (!self::isValidIp($ip)) {
            return false;
        }

        if (self::isPrivateIp($ip)) {
            return true;
        }

        $ipLower = strtolower($ip);
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return true;
        }

        if (strpos($ipLower, '169.254.') === 0 || strpos($ipLower, 'fe80:') === 0) {
            return true;
        }

        if (strpos($ipLower, 'fc') === 0 || strpos($ipLower, 'fd') === 0) {
            return true;
        }

        return false;
    }

    public static function getRequestPath(array $server): string
    {
        $uri = isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '/';
        $queryPos = strpos($uri, '?');
        return $queryPos === false ? $uri : substr($uri, 0, $queryPos);
    }
}
