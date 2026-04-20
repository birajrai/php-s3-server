<?php

namespace S3Gateway\Auth;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Logger;

class PresignedUrlHandler
{
    private Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function validate(): string
    {
        $presignedData = $this->parseParams();
        
        $accessKeyId = $presignedData['Credential']['AccessKeyId'];
        $secretKey = Config::getSecretKey($accessKeyId);

        if ($secretKey === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        $this->checkExpiry($presignedData);

        $currentMethod = $this->request->getMethod();
        $methodsToTry = [$currentMethod];

        if ($currentMethod === 'GET' || $currentMethod === 'HEAD') {
            $methodsToTry[] = $currentMethod === 'GET' ? 'HEAD' : 'GET';
        }

        foreach ($methodsToTry as $method) {
            $stringToSign = $this->buildStringToSign($presignedData, $method);
            $calculatedSignature = $this->calculateSignature($stringToSign, $secretKey, $presignedData);

            if (hash_equals($calculatedSignature, $presignedData['Signature'])) {
                return $accessKeyId;
            }
        }

        throw S3Exception::signatureDoesNotMatch();
    }

    private function parseParams(): array
    {
        $credential = $this->request->getQueryParam('X-Amz-Credential') ??
                      $this->request->getQueryParam('x-amz-credential');
        $algorithm = $this->request->getQueryParam('X-Amz-Algorithm') ??
                     $this->request->getQueryParam('x-amz-algorithm');
        $date = $this->request->getQueryParam('X-Amz-Date') ??
                $this->request->getQueryParam('x-amz-date');
        $expires = $this->request->getQueryParam('X-Amz-Expires') ??
                   $this->request->getQueryParam('x-amz-expires');
        $signedHeaders = $this->request->getQueryParam('X-Amz-SignedHeaders') ??
                          $this->request->getQueryParam('x-amz-signedheaders');
        $signature = $this->request->getQueryParam('X-Amz-Signature') ??
                     $this->request->getQueryParam('x-amz-signature');

        if (empty($credential) || empty($algorithm) || empty($date) ||
            empty($signedHeaders) || empty($signature)) {
            throw S3Exception::accessDenied('Missing required presigned URL parameters');
        }

        $credentialParts = explode('/', $credential);
        if (count($credentialParts) < 5) {
            throw S3Exception::invalidAccessKeyId();
        }

        return [
            'Algorithm' => $algorithm,
            'Credential' => [
                'AccessKeyId' => $credentialParts[0],
                'Date' => $credentialParts[1],
                'Region' => $credentialParts[2],
                'Service' => $credentialParts[3],
                'RequestType' => $credentialParts[4],
            ],
            'AmzDate' => $date,
            'Expires' => $expires ? (int)$expires : null,
            'SignedHeaders' => $signedHeaders,
            'Signature' => $signature,
        ];
    }

    private function checkExpiry(array $presignedData): void
    {
        $expires = $presignedData['Expires'];
        if ($expires === null) {
            return;
        }

        $amzDate = $presignedData['AmzDate'];
        $requestTime = \DateTime::createFromFormat('Ymd\THis\Z', $amzDate, new \DateTimeZone('UTC'));

        if ($requestTime === false) {
            throw S3Exception::invalidRequest('Invalid X-Amz-Date format');
        }

        $expiryTime = clone $requestTime;
        $expiryTime->modify("+{$expires} seconds");

        $now = new \DateTime('now', new \DateTimeZone('UTC'));

        if ($now > $expiryTime) {
            throw S3Exception::expiredToken('Request has expired');
        }
    }

    private function buildStringToSign(array $presignedData, ?string $overrideMethod = null): string
    {
        $method = $overrideMethod ?? $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();

        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->buildCanonicalQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $presignedData['SignedHeaders']);
        $signedHeaders = strtolower($presignedData['SignedHeaders']);

        $hashedPayload = 'UNSIGNED-PAYLOAD';

        $canonicalRequest = implode("\n", [
            $method,
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            '',
            $signedHeaders,
            $hashedPayload,
        ]);

        $amzDate = $presignedData['AmzDate'];
        $date = $presignedData['Credential']['Date'];
        $region = $presignedData['Credential']['Region'];
        $service = $presignedData['Credential']['Service'];
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
            $encodedParts[] = $part === '' ? '' : rawurlencode(rawurldecode($part));
        }
        
        $result = implode('/', $encodedParts);
        
        return str_starts_with($result, '/') ? $result : '/' . $result;
    }

    private function buildCanonicalQueryString(string $queryString): string
    {
        if (empty($queryString)) {
            return '';
        }

        $params = [];
        $pairs = explode('&', $queryString);

        foreach ($pairs as $pair) {
            if (strpos($pair, '=') !== false) {
                list($key, $value) = explode('=', $pair, 2);
                $decodedKey = rawurldecode($key);

                if (strcasecmp($decodedKey, 'X-Amz-Signature') === 0) {
                    continue;
                }

                $params[$decodedKey] = rawurldecode($value);
            } else {
                $decodedKey = rawurldecode($pair);
                if (strcasecmp($decodedKey, 'X-Amz-Signature') === 0) {
                    continue;
                }
                $params[$decodedKey] = '';
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
                $normalizedValue = trim(preg_replace('/\s+/', ' ', $value));
                $canonicalHeaders[] = strtolower($headerName) . ':' . $normalizedValue;
            }
        }

        sort($canonicalHeaders, SORT_STRING);

        return implode("\n", $canonicalHeaders);
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

    private function calculateSignature(string $stringToSign, string $secretKey, array $presignedData): string
    {
        $date = $presignedData['Credential']['Date'];
        $region = $presignedData['Credential']['Region'];
        $service = $presignedData['Credential']['Service'];

        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return hash_hmac('sha256', $stringToSign, $kSigning);
    }
}