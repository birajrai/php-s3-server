<?php

namespace S3Gateway\Auth;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Logger;

class Authenticator
{
    private Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function authenticate(): string
    {
        $authHeader = $this->request->getHeader('Authorization');
        
        $this->log("Auth: {$this->request->getMethod()} {$this->request->getUri()}");

        if ($this->isPresignedUrlRequest()) {
            $handler = new PresignedUrlHandler($this->request);
            $accessKeyId = $handler->validate();
            $this->checkBucketPermission($accessKeyId);
            return $accessKeyId;
        }

        if (empty($authHeader)) {
            throw S3Exception::accessDenied();
        }

        $accessKeyId = null;
        if (strpos($authHeader, 'AWS4-HMAC-SHA256') === 0) {
            $validator = new SignatureValidator($this->request);
            $accessKeyId = $validator->validate($authHeader);
        } elseif (strpos($authHeader, 'AWS ') === 0) {
            $accessKeyId = $this->authenticateV2($authHeader);
        } elseif (strpos($authHeader, 'Bearer ') === 0) {
            $this->authenticateBearer($authHeader);
            return '';
        } else {
            throw S3Exception::accessDenied();
        }
        
        $this->checkBucketPermission($accessKeyId);
        return $accessKeyId;
    }

    public function checkRequestSize(string $accessKeyId): void
    {
        $contentLength = $this->request->getHeader('Content-Length');
        $maxSize = Config::getFileMaxSize($accessKeyId);

        if ($maxSize > 0 && $contentLength !== null && (int)$contentLength > $maxSize) {
            throw S3Exception::entityTooLarge((int)$contentLength, $maxSize);
        }
    }

    private function isPresignedUrlRequest(): bool
    {
        return $this->request->hasQueryParam('X-Amz-Credential') ||
               $this->request->hasQueryParam('x-amz-credential');
    }

    private function extractBucketName(): ?string
    {
        $uri = $this->request->getUri();
        $parts = explode('/', ltrim($uri, '/'));
        
        if (count($parts) > 0 && !empty($parts[0])) {
            return $parts[0];
        }
        
        return null;
    }

    private function checkBucketPermission(string $accessKeyId): void
    {
        $bucketName = $this->extractBucketName();
        if ($bucketName) {
            if (!Config::isBucketAllowed($accessKeyId, $bucketName)) {
                throw S3Exception::accessDenied("Access denied for bucket: {$bucketName}");
            }
        }
    }

    private function authenticateV2(string $authHeader): string
    {
        $pattern = '/AWS\s+([^:]+):(.+)/';
        if (!preg_match($pattern, $authHeader, $matches)) {
            throw S3Exception::accessDenied();
        }

        $accessKeyId = $matches[1];
        $signature = $matches[2];

        $secretKey = Config::getSecretKey($accessKeyId);
        if ($secretKey === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        $stringToSign = $this->request->getMethod() . "\n\n\n" . 
                        $this->request->getHeader('Date') . "\n" . 
                        $this->request->getUri();

        $expectedSignature = base64_encode(hash_hmac('sha1', $stringToSign, $secretKey, true));

        if (!hash_equals($expectedSignature, $signature)) {
            throw S3Exception::signatureDoesNotMatch();
        }

        return $accessKeyId;
    }

    private function authenticateBearer(string $authHeader): void
    {
        $token = substr($authHeader, 7);
        $validToken = Config::bearerToken();

        if ($validToken === null || !hash_equals($validToken, $token)) {
            throw S3Exception::accessDenied();
        }
    }

    private function log(string $message): void
    {
        if (Logger::debugEnabled()) {
            Logger::debug("[Authenticator] {$message}");
        }
    }
}