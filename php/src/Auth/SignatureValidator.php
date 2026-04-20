<?php

namespace S3Gateway\Auth;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Logger;

class SignatureValidator
{
    private const MAX_TIMESTAMP_SKEW = 300;
    private const HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'x-amzn-trace-id'
    ];

    private Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function validate(string $authHeader): string
    {
        $this->log("Validating AWS4-HMAC-SHA256 signature");

        $signatureData = $this->parseAuthHeader($authHeader);
        $accessKeyId = $signatureData['Credential']['AccessKeyId'] ?? null;

        if ($accessKeyId === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        $secretKey = Config::getSecretKey($accessKeyId);
        if ($secretKey === null) {
            $this->log("Secret key not found for: {$accessKeyId}");
            throw S3Exception::invalidAccessKeyId();
        }

        $this->validateTimestamp($signatureData);

        $currentMethod = $this->request->getMethod();
        $methodsToTry = [$currentMethod];

        if ($currentMethod === 'GET' || $currentMethod === 'HEAD') {
            $methodsToTry[] = $currentMethod === 'GET' ? 'HEAD' : 'GET';
        }

        foreach ($methodsToTry as $method) {
            $stringToSign = $this->buildStringToSign($signatureData, $method);
            $calculatedSignature = $this->calculateSignature($stringToSign, $secretKey, $signatureData);

            if (hash_equals($calculatedSignature, $signatureData['Signature'])) {
                $this->log("Signature verified with method: {$method}");
                return $accessKeyId;
            }
        }

        throw S3Exception::signatureDoesNotMatch();
    }

    private function parseAuthHeader(string $authHeader): array
    {
        $cleanedHeader = str_replace(["\r\n", "\r", "\n"], ' ', $authHeader);
        $cleanedHeader = preg_replace('/\s+/', ' ', $cleanedHeader);
        $cleanedHeader = trim($cleanedHeader);

        $pattern = '/AWS4-HMAC-SHA256\s+Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([a-f0-9]+)/i';

        if (!preg_match($pattern, $cleanedHeader, $matches)) {
            throw S3Exception::accessDenied('Invalid Authorization header format');
        }

        $credential = $matches[1];
        $signedHeaders = $matches[2];
        $signature = $matches[3];

        $credentialParts = explode('/', $credential);
        if (count($credentialParts) < 5) {
            throw S3Exception::invalidAccessKeyId();
        }

        return [
            'Credential' => [
                'AccessKeyId' => $credentialParts[0],
                'Date' => $credentialParts[1],
                'Region' => $credentialParts[2],
                'Service' => $credentialParts[3],
                'RequestType' => $credentialParts[4],
            ],
            'SignedHeaders' => $signedHeaders,
            'Signature' => $signature,
        ];
    }

    private function validateTimestamp(array $signatureData): void
    {
        $amzDate = $this->getAmzDate();
        if (empty($amzDate)) {
            throw S3Exception::invalidRequest('X-Amz-Date header is required');
        }

        $requestTime = \DateTime::createFromFormat('Ymd\THis\Z', $amzDate, new \DateTimeZone('UTC'));
        if ($requestTime === false) {
            throw S3Exception::invalidRequest('Invalid X-Amz-Date format');
        }

        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $diff = abs($now->getTimestamp() - $requestTime->getTimestamp());

        if ($diff > self::MAX_TIMESTAMP_SKEW) {
            throw S3Exception::expiredToken('Request timestamp skew too large');
        }
    }

    private function getAmzDate(): string
    {
        $headers = $this->request->getHeaders();
        
        $amzDate = $this->findHeader($headers, 'x-amz-date');
        if ($amzDate !== null) {
            return $amzDate;
        }

        $dateHeader = $this->findHeader($headers, 'date');
        if ($dateHeader !== null) {
            $timestamp = strtotime($dateHeader);
            if ($timestamp !== false) {
                return gmdate('Ymd\THis\Z', $timestamp);
            }
        }

        return gmdate('Ymd\THis\Z');
    }

    private function buildStringToSign(array $signatureData, ?string $overrideMethod = null): string
    {
        $method = $overrideMethod ?? $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();
        $body = $this->request->getBody();

        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->normalizeQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $signatureData['SignedHeaders']);
        $signedHeaders = strtolower($signatureData['SignedHeaders']);
        $hashedPayload = $this->getPayloadHash($headers, $body, $method);

        $canonicalRequest = implode("\n", [
            $method,
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            '',
            $signedHeaders,
            $hashedPayload,
        ]);

        $amzDate = $this->getAmzDate();
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];
        $scope = "{$date}/{$region}/{$service}/aws4_request";

        return implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);
    }

    private function encodeUri(string $uri): string
    {
        $uri = $uri ?: '/';
        
        $parts = explode('/', $uri);
        $encodedParts = [];
        
        foreach ($parts as $part) {
            if ($part === '') {
                $encodedParts[] = '';
            } else {
                $decoded = rawurldecode($part);
                $encodedParts[] = rawurlencode($decoded);
            }
        }
        
        $result = implode('/', $encodedParts);
        
        if (!str_starts_with($result, '/')) {
            $result = '/' . $result;
        }
        
        return $result;
    }

    private function normalizeQueryString(string $queryString): string
    {
        if (empty($queryString)) {
            return '';
        }

        $params = [];
        $pairs = explode('&', $queryString);
        
        foreach ($pairs as $pair) {
            if (strpos($pair, '=') !== false) {
                list($key, $value) = explode('=', $pair, 2);
                $params[rawurldecode($key)] = rawurldecode($value);
            } else {
                $params[rawurldecode($pair)] = '';
            }
        }

        ksort($params, SORT_STRING);

        $normalized = [];
        foreach ($params as $key => $value) {
            $normalized[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $normalized);
    }

    private function buildCanonicalHeaders(array $headers, string $signedHeaders): string
    {
        $signedHeadersList = explode(';', strtolower($signedHeaders));
        $canonicalHeaders = [];

        foreach ($signedHeadersList as $headerName) {
            $headerName = trim($headerName);
            if (empty($headerName)) {
                continue;
            }
            
            $value = $this->findHeader($headers, $headerName);
            if ($value !== null) {
                $normalizedValue = $this->normalizeHeaderValue($value);
                $canonicalHeaders[] = strtolower($headerName) . ':' . $normalizedValue;
            }
        }

        sort($canonicalHeaders, SORT_STRING);

        return implode("\n", $canonicalHeaders);
    }

    private function normalizeHeaderValue(string $value): string
    {
        $value = trim($value);
        $value = preg_replace('/\s+/', ' ', $value);
        return $value;
    }

    private function findHeader(array $headers, string $name): ?string
    {
        $name = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower($key) === $name) {
                return $value;
            }
        }
        return null;
    }

    private function getPayloadHash(array $headers, string $body, ?string $overrideMethod = null): string
    {
        $contentSha256 = $this->findHeader($headers, 'x-amz-content-sha256');
        if ($contentSha256 !== null) {
            return $contentSha256;
        }

        $method = $overrideMethod ?? $this->request->getMethod();
        
        $emptyPayloadMethods = ['HEAD', 'GET', 'DELETE'];
        if (in_array($method, $emptyPayloadMethods)) {
            return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        }

        return hash('sha256', $body);
    }

    private function calculateSignature(string $stringToSign, string $secretKey, array $signatureData): string
    {
        $amzDate = $this->getAmzDate();
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];

        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    private function log(string $message): void
    {
        if (Logger::debugEnabled()) {
            Logger::debug("[SignatureValidator] {$message}");
        }
    }
}