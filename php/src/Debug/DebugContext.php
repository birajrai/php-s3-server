<?php

namespace S3Gateway\Debug;

class DebugContext
{
    private string $requestId;
    private float $startTime;
    private string $method = '';
    private string $uri = '';
    private array $data = [];

    public function __construct()
    {
        $this->requestId = substr(bin2hex(random_bytes(8)), 0, 12);
        $this->startTime = microtime(true);
    }

    public function requestId(): string
    {
        return $this->requestId;
    }

    public function setRequest(string $method, string $uri): void
    {
        $this->method = $method;
        $this->uri = $uri;
    }

    public function set(string $key, $value): void
    {
        $this->data[$key] = $value;
    }

    public function get(string $key)
    {
        return $this->data[$key] ?? null;
    }

    public function elapsed(): float
    {
        return round((microtime(true) - $this->startTime) * 1000, 2);
    }

    public function summary(): array
    {
        return [
            'requestId' => $this->requestId,
            'method' => $this->method,
            'uri' => $this->uri,
            'elapsed_ms' => $this->elapsed(),
            'data' => $this->data,
        ];
    }

    public static function formatElapsed(float $ms): string
    {
        if ($ms < 1) {
            return '<1ms';
        }
        if ($ms < 1000) {
            return round($ms, 1) . 'ms';
        }
        return round($ms / 1000, 2) . 's';
    }
}