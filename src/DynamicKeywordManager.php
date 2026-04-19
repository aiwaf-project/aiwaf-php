<?php
namespace AIWAF;

use AIWAF\Core\KeywordFallbackStore;

class DynamicKeywordManager
{
    private static $keywords = ['admin', '.env', '.git'];

    private static function store(): KeywordFallbackStore
    {
        return new KeywordFallbackStore(Config::DYNAMIC_KEYWORDS_PATH);
    }

    private static function hydrateFromStore(): void
    {
        $stored = array_keys(self::store()->all());
        if (!empty($stored)) {
            self::$keywords = array_values(array_unique(array_merge(self::$keywords, $stored)));
        }
    }

    public static function detect(string $path): int
    {
        self::hydrateFromStore();
        $count = 0;
        foreach (self::$keywords as $keyword) {
            if (strpos($path, $keyword) !== false) {
                $count++;
            }
        }
        return $count;
    }

    public static function learn(string $path): void
    {
        self::hydrateFromStore();
        if (!in_array($path, self::$keywords)) {
            self::$keywords[] = $path;
            self::store()->add($path);
        }
    }

    public static function addKeywords(array $newKeywords): bool
    {
        self::hydrateFromStore();
        foreach ($newKeywords as $keyword) {
            if (!in_array($keyword, self::$keywords)) {
                self::$keywords[] = $keyword;
                self::store()->add($keyword);
            }
        }
        return true;
    }

    public static function removeKeywords(array $keywordsToRemove): bool
    {
        self::hydrateFromStore();
        self::$keywords = array_values(array_filter(self::$keywords, function ($keyword) use ($keywordsToRemove) {
            return !in_array($keyword, $keywordsToRemove);
        }));

        $store = self::store();
        foreach ($keywordsToRemove as $keyword) {
            $store->remove($keyword);
        }

        return true;
    }

    public static function resetKeywords(): void
    {
        self::$keywords = ['admin', '.env', '.git'];
        foreach (array_keys(self::store()->all()) as $keyword) {
            self::store()->remove($keyword);
        }
    }

    public static function getKeywords(): array
    {
        self::hydrateFromStore();
        return self::$keywords;
    }

    public static function topKeywords(int $n = 10): array
    {
        return self::store()->top($n);
    }
}
