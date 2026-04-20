<?php

namespace S3Gateway\Debug;

trait DebugLoggerTrait
{
    private DebugLogger $debug;

    private function debug(): DebugLogger
    {
        if (!isset($this->debug)) {
            $this->debug = new DebugLogger();
        }
        return $this->debug;
    }

    private function log(string $context, string $message, array $data = []): void
    {
        DebugLogger::log($context, $message, $data);
    }

    private function logStart(string $context, array $data = []): void
    {
        DebugLogger::start($context, $data);
    }

    private function logSuccess(string $context, array $data = []): void
    {
        DebugLogger::success($context, $data);
    }

    private function logError(string $context, string $message, array $data = []): void
    {
        DebugLogger::error($context, $message, $data);
    }

    private function logInfo(string $context, string $message, array $data = []): void
    {
        DebugLogger::log($context, $message, $data);
    }
}