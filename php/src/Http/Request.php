<?php

namespace S3Gateway\Http;

use S3Gateway\Logger;

class Request
{
    private string $method;
    private string $uri;
    private string $queryString;
    private array $headers = [];
    private string $body = '';
    private string $bucket = '';
    private string $key = '';
    private array $queryParams = [];

    public function __construct()
    {
        $originalMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->method = $originalMethod;
        
        $this->detectAndRestoreHeadRequest($originalMethod);
        $this->uri = $this->parseUri();
        $this->queryString = $_SERVER['QUERY_STRING'] ?? '';
        
        $this->logRequestArrival();
        
        $this->headers = $this->parseHeaders();
        $this->body = $this->readBody();
        $this->parsePath();
        $this->parseQueryParams();
    }
    
    private function detectAndRestoreHeadRequest(string $originalMethod): void
    {
        if ($originalMethod === 'HEAD') {
            $this->method = 'HEAD';
            return;
        }

        if ($originalMethod !== 'GET') {
            return;
        }

        if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']) && strtoupper($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']) === 'HEAD') {
            $this->method = 'HEAD';
            return;
        }

        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (stripos($name, 'x-http-method') !== false && stripos($value, 'HEAD') !== false) {
                    $this->method = 'HEAD';
                    return;
                }
            }
        }
    }
    
    private function logRequestArrival(): void
    {
        if (!Logger::debugEnabled()) {
            return;
        }

        Logger::debug("Request: {$this->method} {$this->uri}");
    }

    private function parseUri(): string
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $pos = strpos($uri, '?');
        if ($pos !== false) {
            $uri = substr($uri, 0, $pos);
        }
        return $uri;
    }

    private function parseHeaders(): array
    {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $headerKey = strtoupper($headerName);
                if ($value !== null) {
                    $value = str_replace(["\r\n", "\r", "\n"], ' ', $value);
                    $value = preg_replace('/\s+/', ' ', $value);
                    $value = trim($value);
                }
                $headers[$headerKey] = $value;
            }
        }

        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['CONTENT-TYPE'] = $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $headers['CONTENT-LENGTH'] = $_SERVER['CONTENT_LENGTH'];
        }
        if (isset($_SERVER['HTTP_RANGE'])) {
            $headers['RANGE'] = $_SERVER['HTTP_RANGE'];
        }

        if (isset($headers['X-FORWARDED-HOST'])) {
            $headers['HOST'] = $headers['X-FORWARDED-HOST'];
        }

        return $headers;
    }

    private function readBody(): string
    {
        if ($this->method === 'HEAD') {
            return '';
        }

        $contentEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? '';
        $body = file_get_contents('php://input');

        if ($body === false || $body === '') {
            return '';
        }

        if ($contentEncoding === 'aws-chunked' || strpos($body, ';chunk-signature=') !== false) {
            return $this->decodeAwsChunked($body);
        }

        if ($this->isChunked($body)) {
            return $this->decodeChunked($body);
        }

        return $body;
    }

    private function isChunked(string $body): bool
    {
        return preg_match('/^[0-9a-fA-F]+\r\n/', $body) === 1;
    }

    private function decodeChunked(string $body): string
    {
        $decoded = '';
        $pos = 0;
        $len = strlen($body);

        while ($pos < $len) {
            $lineEnd = strpos($body, "\r\n", $pos);
            if ($lineEnd === false) {
                break;
            }

            $sizeHex = substr($body, $pos, $lineEnd - $pos);
            $size = hexdec(trim($sizeHex));

            if ($size === 0) {
                break;
            }

            $dataStart = $lineEnd + 2;
            $dataEnd = $dataStart + $size;

            if ($dataEnd > $len) {
                break;
            }

            $decoded .= substr($body, $dataStart, $size);
            $pos = $dataEnd + 2;
        }

        return $decoded;
    }

    private function decodeAwsChunked(string $body): string
    {
        $decoded = '';
        $pos = 0;
        $len = strlen($body);

        while ($pos < $len) {
            $lineEnd = strpos($body, "\r\n", $pos);
            if ($lineEnd === false) {
                break;
            }

            $chunkHeader = substr($body, $pos, $lineEnd - $pos);
            $semicolonPos = strpos($chunkHeader, ';');
            $sizeHex = $semicolonPos === false 
                ? trim($chunkHeader) 
                : trim(substr($chunkHeader, 0, $semicolonPos));

            $size = hexdec($sizeHex);

            if ($size === 0) {
                break;
            }

            $dataStart = $lineEnd + 2;
            $dataEnd = $dataStart + $size;

            if ($dataEnd > $len) {
                break;
            }

            $decoded .= substr($body, $dataStart, $size);
            $pos = $dataEnd + 2;
        }

        return $decoded;
    }

    private function parsePath(): void
    {
        $path = trim($this->uri, '/');
        $parts = explode('/', $path, 2);

        $this->bucket = $parts[0] ?? '';

        if (isset($parts[1])) {
            $this->key = $parts[1];
        }
    }

    private function parseQueryParams(): void
    {
        parse_str($this->queryString, $this->queryParams);
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getUri(): string
    {
        return $this->uri;
    }

    public function getQueryString(): string
    {
        return $this->queryString;
    }

    public function getHeader(string $name): ?string
    {
        $key = strtoupper(str_replace('-', '_', $name));
        
        foreach ($this->headers as $headerKey => $value) {
            if (strcasecmp($headerKey, $key) === 0 || strcasecmp($headerKey, $name) === 0) {
                return $value;
            }
        }
        
        return null;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getBody(): string
    {
        return $this->body;
    }

    public function getBucket(): string
    {
        return $this->bucket;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getQueryParam(string $name): ?string
    {
        return $this->queryParams[$name] ?? null;
    }

    public function hasQueryParam(string $name): bool
    {
        return isset($this->queryParams[$name]);
    }

    public function isPreflight(): bool
    {
        return $this->method === 'OPTIONS';
    }
}