<?php

namespace S3Gateway\Validation;

use S3Gateway\Exception\S3Exception;

trait ObjectKeyValidation
{
    protected function requireKey(string $key): void
    {
        if (empty($key)) {
            throw S3Exception::invalidRequest('Key required');
        }
    }

    protected function requireKeyExists(string $bucket, string $key): void
    {
        $pathResolver = $this->getStorage()->getPathResolver();
        $filePath = $pathResolver->objectPath($bucket, $key);
        
        if (!file_exists($filePath)) {
            throw S3Exception::noSuchKey("/{$bucket}/{$key}");
        }
    }

    protected function validateKeyLength(string $key): void
    {
        if (strlen($key) > 1024) {
            throw S3Exception::invalidRequest('Key length exceeds maximum of 1024 characters');
        }
    }
}