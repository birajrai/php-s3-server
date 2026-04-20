<?php

namespace S3Gateway\Debug;

use S3Gateway\Config;
use S3Gateway\Logger;

class DebugLogger
{
    private static bool $enabled = false;
    private static string $prefix = '';

    public static function init(): void
    {
        self::$enabled = Config::appDebug();
    }

    public static function enabled(): bool
    {
        return self::$enabled;
    }

    public static function setPrefix(string $prefix): void
    {
        self::$prefix = $prefix;
    }

    public static function log(string $context, string $message, array $data = []): void
    {
        if (!self::$enabled) {
            return;
        }

        $tag = self::$prefix ? "[{$context}] [{$context}]" : "[{$context}]";
        
        if (empty($data)) {
            Logger::debug("{$tag} {$message}");
            return;
        }

        $pairs = [];
        foreach ($data as $key => $value) {
            $pairs[] = "{$key}=" . (is_bool($value) ? ($value ? 'yes' : 'no') : $value);
        }
        
        Logger::debug("{$tag} {$message}: " . implode(', ', $pairs));
    }

    public static function start(string $context, array $data = []): void
    {
        self::log($context, 'Start', $data);
    }

    public static function success(string $context, array $data = []): void
    {
        self::log($context, 'Success', $data);
    }

    public static function error(string $context, string $message, array $data = []): void
    {
        self::log($context, "Error: {$message}", $data);
    }

    public static function info(string $context, string $message, array $data = []): void
    {
        self::log($context, $message, $data);
    }

    public static function request(string $method, string $uri): void
    {
        if (!self::$enabled) {
            return;
        }

        Logger::debug("Request: {$method} {$uri}");
    }

    public static function response(int $statusCode, ?string $bodyPreview = null): void
    {
        if (!self::$enabled) {
            return;
        }

        $message = "Response: {$statusCode}";
        if ($bodyPreview !== null && strlen($bodyPreview) > 0) {
            $preview = strlen($bodyPreview) > 100 
                ? substr($bodyPreview, 0, 100) . '...' 
                : $bodyPreview;
            $message .= " - {$preview}";
        }

        Logger::debug($message);
    }

    public static function headers(array $headers, string $label = ''): void
    {
        if (!self::$enabled) {
            return;
        }

        $label = $label ? "{$label}: " : '';
        foreach ($headers as $name => $value) {
            Logger::debug("{$label}{$name}: {$value}");
        }
    }
}