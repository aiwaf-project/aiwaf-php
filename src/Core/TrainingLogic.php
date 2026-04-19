<?php

declare(strict_types=1);

namespace AIWAF\Core;

final class TrainingLogic
{
    public static function isScanningPath(string $path): bool
    {
        $pathLower = strtolower($path);

        $scanningPatterns = [
            'admin', 'adminer', 'config', 'configuration',
            'settings', 'setup', 'install', 'installer',
            'backup', 'database', 'db', 'mysql', 'sql', 'dump',
            '.env', '.git', '.htaccess', '.htpasswd', 'passwd', 'shadow',
            'cgi-bin', 'scripts', 'shell', 'cmd', 'exec',
            '.asp', '.aspx', '.jsp', '.cgi', '.pl',
        ];

        foreach ($scanningPatterns as $pattern) {
            if (strpos($pathLower, $pattern) !== false) {
                return true;
            }
        }

        if (strpos($path, '../') !== false || strpos($path, '..') !== false) {
            return true;
        }

        foreach (['%2e%2e', '%252e', '%c0%ae'] as $encoded) {
            if (strpos($pathLower, $encoded) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    public static function getDefaultLegitimateKeywords(): array
    {
        return array_values(array_unique([
            'profile', 'user', 'users', 'account', 'accounts', 'settings', 'dashboard',
            'home', 'about', 'contact', 'help', 'search', 'list', 'lists',
            'view', 'views', 'edit', 'create', 'update', 'delete', 'detail', 'details',
            'api', 'auth', 'login', 'logout', 'register', 'signup', 'signin',
            'reset', 'confirm', 'activate', 'verify', 'page', 'pages',
            'category', 'categories', 'tag', 'tags', 'post', 'posts',
            'article', 'articles', 'blog', 'blogs', 'news', 'item', 'items',
            'admin', 'administration', 'manage', 'manager', 'control', 'panel',
            'config', 'configuration', 'option', 'options', 'preference', 'preferences',

            'contenttypes', 'contenttype', 'sessions', 'session', 'messages', 'message',
            'staticfiles', 'static', 'sites', 'site', 'flatpages', 'flatpage',
            'redirects', 'redirect', 'permissions', 'permission', 'groups', 'group',

            'token', 'tokens', 'oauth', 'social', 'rest', 'framework', 'cors',
            'debug', 'toolbar', 'extensions', 'allauth', 'crispy', 'forms',
            'channels', 'celery', 'redis', 'cache', 'email', 'mail',

            'static', 'favicon', 'robots', 'sitemap', 'manifest', 'health', 'ping',
            'status', 'metrics', 'test', 'docs', 'documentation',

            'endpoint', 'endpoints', 'resource', 'resources', 'data', 'export',
            'import', 'upload', 'download', 'file', 'files', 'media', 'images',
            'documents', 'reports', 'analytics', 'stats', 'statistics',

            'customer', 'customers', 'client', 'clients', 'company', 'companies',
            'department', 'departments', 'employee', 'employees', 'team', 'teams',
            'project', 'projects', 'task', 'tasks', 'event', 'events',
            'notification', 'notifications', 'alert', 'alerts',

            'language', 'languages', 'locale', 'locales', 'translation', 'translations',
            'en', 'fr', 'de', 'es', 'it', 'pt', 'ru', 'ja', 'zh', 'ko',
        ]));
    }

    /**
     * @param array<int, string> $staticKeywords
     */
    public static function isMaliciousContext(
        string $path,
        string $keyword,
        string $status,
        array $staticKeywords,
        ?callable $pathExistsFn = null
    ): bool {
        if ($pathExistsFn !== null) {
            try {
                if ($pathExistsFn($path)) {
                    return false;
                }
            } catch (\Throwable $e) {
                // Preserve Python behavior: ignore path-existence lookup failures.
            }
        }

        $pathLower = strtolower($path);
        $segments = preg_split('/\W+/', $pathLower, -1, PREG_SPLIT_NO_EMPTY);
        if ($segments === false) {
            $segments = [];
        }

        $keywordLookup = [];
        foreach ($staticKeywords as $kw) {
            $keywordLookup[strtolower($kw)] = true;
        }

        $staticKwHits = 0;
        foreach ($segments as $segment) {
            if (isset($keywordLookup[$segment])) {
                $staticKwHits++;
            }
        }

        $hasPattern = self::containsAny($pathLower, [
            '../', '..\\', '.env', 'config',
            'backup', 'database', 'mysql', 'passwd', 'shadow',
            'shell', 'cmd', 'exec', 'eval', 'system',
        ]);

        $hasAttackPayload = self::containsAny($pathLower, [
            'union+select', 'drop+table', '<script', 'javascript:',
            '${', '{{', 'onload=', 'onerror=', 'file://', 'http://',
        ]);

        $repeatedTraversal = substr_count($pathLower, '../') > 1 || substr_count($pathLower, '..\\') > 1;

        $hasEncodedPayload = self::containsAny($pathLower, [
            '%2e%2e', '%252e', '%c0%ae', '%3c%73%63%72%69%70%74',
        ]);

        $suspicious404Shape = $status === '404' && (
            strlen($pathLower) > 50 ||
            substr_count($pathLower, '/') > 10 ||
            self::containsAny($pathLower, ['<', '>', '{', '}', '$', '`'])
        );

        return (
            $staticKwHits > 1 ||
            $hasPattern ||
            $hasAttackPayload ||
            $repeatedTraversal ||
            $hasEncodedPayload ||
            $suspicious404Shape
        );
    }

    /**
     * @param array<int, string> $needles
     */
    private static function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (strpos($haystack, $needle) !== false) {
                return true;
            }
        }

        return false;
    }
}
