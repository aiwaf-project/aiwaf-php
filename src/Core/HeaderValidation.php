<?php
namespace AIWAF\Core;

final class HeaderValidation
{
    private const MAX_HEADER_BYTES = 32768;
    private const MAX_HEADER_COUNT = 100;
    private const MAX_USER_AGENT_LENGTH = 500;
    private const MAX_ACCEPT_LENGTH = 4096;

    private const BROWSER_HEADERS = [
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_CONNECTION',
        'HTTP_CACHE_CONTROL',
    ];

    private const SUSPICIOUS_UA_PATTERNS = [
        '/bot/i', '/crawler/i', '/spider/i', '/scraper/i', '/curl/i', '/wget/i', '/python/i',
        '/java/i', '/node/i', '/go-http/i', '/axios/i', '/okhttp/i', '/libwww/i', '/lwp-trivial/i',
        '/mechanize/i', '/requests/i', '/urllib/i', '/httpie/i', '/postman/i', '/insomnia/i', '/^$/i',
        '/mozilla\/4\.0$/i',
    ];

    private const LEGITIMATE_BOTS = [
        '/googlebot/i', '/bingbot/i', '/slurp/i', '/duckduckbot/i', '/baiduspider/i', '/yandexbot/i',
        '/facebookexternalhit/i', '/twitterbot/i', '/linkedinbot/i', '/whatsapp/i', '/telegrambot/i',
        '/applebot/i', '/pingdom/i', '/uptimerobot/i', '/statuscake/i', '/site24x7/i',
    ];

    /**
     * @param array<int, string>|array<string, array<int, string>> $requiredHeaders
     * @param array<string, mixed> $options
     */
    public static function validate(array $server, $requiredHeaders = ['HTTP_USER_AGENT', 'HTTP_ACCEPT'], int $minScore = 3, ?string $method = null, array $options = []): ?string
    {
        $totalBytes = 0;
        $headerCount = 0;

        foreach ($server as $key => $value) {
            if (!is_string($key)) {
                continue;
            }
            if (strpos($key, 'HTTP_') !== 0 && $key !== 'CONTENT_TYPE' && $key !== 'CONTENT_LENGTH') {
                continue;
            }

            $headerCount++;
            $valueStr = is_scalar($value) ? (string) $value : json_encode($value);
            $totalBytes += strlen($key) + strlen((string) $valueStr);

            if ($totalBytes > self::MAX_HEADER_BYTES) {
                return 'Header bytes exceed ' . self::MAX_HEADER_BYTES;
            }
        }

        if ($headerCount > self::MAX_HEADER_COUNT) {
            return 'Header count exceeds ' . self::MAX_HEADER_COUNT;
        }

        $userAgent = isset($server['HTTP_USER_AGENT']) ? (string) $server['HTTP_USER_AGENT'] : '';
        $accept = isset($server['HTTP_ACCEPT']) ? (string) $server['HTTP_ACCEPT'] : '';

        if ($userAgent !== '' && strlen($userAgent) > self::MAX_USER_AGENT_LENGTH) {
            return 'User-Agent longer than ' . self::MAX_USER_AGENT_LENGTH . ' chars';
        }
        if ($accept !== '' && strlen($accept) > self::MAX_ACCEPT_LENGTH) {
            return 'Accept header longer than ' . self::MAX_ACCEPT_LENGTH . ' chars';
        }

        $resolvedRequiredHeaders = self::resolveRequiredHeaders($requiredHeaders, $method ?? (string) ($server['REQUEST_METHOD'] ?? ''));

        $missing = [];
        foreach ($resolvedRequiredHeaders as $header) {
            if (!isset($server[$header]) || (string) $server[$header] === '') {
                $missing[] = strtolower(str_replace('_', '-', str_replace('HTTP_', '', $header)));
            }
        }
        if (!empty($missing)) {
            return 'Missing required headers: ' . implode(', ', $missing);
        }

        $trustLegitimateBots = isset($options['trust_legitimate_bots']) ? (bool) $options['trust_legitimate_bots'] : true;
        $legitimatePatterns = self::buildLegitimatePatterns($options);
        $suspiciousPatterns = self::buildSuspiciousPatterns($options);

        if ($trustLegitimateBots) {
            foreach ($legitimatePatterns as $pattern) {
                if ($userAgent !== '' && preg_match($pattern, $userAgent) === 1) {
                    return null;
                }
            }
        }

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent) === 1) {
                return 'Suspicious user agent: Pattern: ' . trim($pattern, '/i');
            }
        }

        if ($userAgent !== '' && strlen($userAgent) < 10) {
            return 'Suspicious user agent: Too short';
        }

        if (($server['SERVER_PROTOCOL'] ?? '') === 'HTTP/2' && stripos($userAgent, 'mozilla/4.0') !== false) {
            return 'Suspicious headers: HTTP/2 with old browser user agent';
        }

        if ($userAgent !== '' && $accept === '' && in_array('HTTP_ACCEPT', $resolvedRequiredHeaders, true)) {
            return 'Suspicious headers: User-Agent present but no Accept header';
        }

        if ($accept === '*/*' && (!isset($server['HTTP_ACCEPT_LANGUAGE']) && !isset($server['HTTP_ACCEPT_ENCODING']))) {
            return 'Suspicious headers: Generic Accept header without language/encoding';
        }

        if ($userAgent !== ''
            && empty($server['HTTP_ACCEPT_LANGUAGE'])
            && empty($server['HTTP_ACCEPT_ENCODING'])
            && empty($server['HTTP_CONNECTION'])) {
            return 'Suspicious headers: Missing all browser-standard headers';
        }

        if (($server['SERVER_PROTOCOL'] ?? '') === 'HTTP/1.0' && stripos($userAgent, 'chrome') !== false) {
            return 'Suspicious headers: Modern browser with HTTP/1.0';
        }

        $score = self::calculateQualityScore($server);
        if (!empty($resolvedRequiredHeaders) && $score < $minScore) {
            return 'Low header quality score: ' . $score;
        }

        return null;
    }

    /**
     * @param array<int, string>|array<string, array<int, string>> $requiredHeaders
     * @return array<int, string>
     */
    private static function resolveRequiredHeaders($requiredHeaders, string $method): array
    {
        if (!is_array($requiredHeaders)) {
            return ['HTTP_USER_AGENT', 'HTTP_ACCEPT'];
        }

        // Flat list form: ['HTTP_USER_AGENT', 'HTTP_ACCEPT']
        if (array_values($requiredHeaders) === $requiredHeaders) {
            return array_values(array_filter($requiredHeaders, static function ($header): bool {
                return is_string($header) && $header !== '';
            }));
        }

        // Mapping form: ['DEFAULT' => [...], 'GET' => [...], 'POST' => [...]]
        $methodUpper = strtoupper($method);
        if ($methodUpper !== '' && isset($requiredHeaders[$methodUpper]) && is_array($requiredHeaders[$methodUpper])) {
            return array_values(array_filter($requiredHeaders[$methodUpper], static function ($header): bool {
                return is_string($header) && $header !== '';
            }));
        }

        if (isset($requiredHeaders['DEFAULT']) && is_array($requiredHeaders['DEFAULT'])) {
            return array_values(array_filter($requiredHeaders['DEFAULT'], static function ($header): bool {
                return is_string($header) && $header !== '';
            }));
        }

        return ['HTTP_USER_AGENT', 'HTTP_ACCEPT'];
    }

    private static function calculateQualityScore(array $server): int
    {
        $score = 0;

        if (!empty($server['HTTP_USER_AGENT'])) {
            $score += 2;
        }
        if (!empty($server['HTTP_ACCEPT'])) {
            $score += 2;
        }

        foreach (self::BROWSER_HEADERS as $header) {
            if (!empty($server[$header])) {
                $score++;
            }
        }

        if (!empty($server['HTTP_ACCEPT_LANGUAGE']) && !empty($server['HTTP_ACCEPT_ENCODING'])) {
            $score++;
        }

        if (($server['HTTP_CONNECTION'] ?? '') === 'keep-alive') {
            $score++;
        }

        $accept = (string) ($server['HTTP_ACCEPT'] ?? '');
        if (strpos($accept, 'text/html') !== false && strpos($accept, 'application/xml') !== false) {
            $score++;
        }

        return $score;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<int, string>
     */
    private static function buildSuspiciousPatterns(array $options): array
    {
        $patterns = self::SUSPICIOUS_UA_PATTERNS;
        $custom = $options['custom_suspicious_patterns'] ?? [];
        if (!is_array($custom)) {
            return $patterns;
        }

        foreach ($custom as $pattern) {
            $compiled = self::compilePattern($pattern);
            if ($compiled !== null) {
                $patterns[] = $compiled;
            }
        }

        return $patterns;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<int, string>
     */
    private static function buildLegitimatePatterns(array $options): array
    {
        $patterns = self::LEGITIMATE_BOTS;
        $custom = $options['custom_legitimate_patterns'] ?? [];
        if (!is_array($custom)) {
            return $patterns;
        }

        foreach ($custom as $pattern) {
            $compiled = self::compilePattern($pattern);
            if ($compiled !== null) {
                $patterns[] = $compiled;
            }
        }

        return $patterns;
    }

    private static function compilePattern($pattern): ?string
    {
        if (!is_string($pattern)) {
            return null;
        }

        $trimmed = trim($pattern);
        if ($trimmed === '') {
            return null;
        }

        if ($trimmed[0] === '/' && substr($trimmed, -2) === '/i') {
            return $trimmed;
        }

        if ($trimmed[0] === '/' && substr($trimmed, -1) === '/') {
            return $trimmed . 'i';
        }

        return '/' . preg_quote($trimmed, '/') . '/i';
    }
}
