<?php

namespace S3Gateway\Validation;

use S3Gateway\Exception\S3Exception;
use S3Gateway\Storage\FileStorage;

trait BucketValidation
{
    abstract protected function getStorage(): FileStorage;

    protected function requireBucket(string $bucket): void
    {
        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }
    }

    protected function requireBucketExists(string $bucket): void
    {
        if (!$this->getStorage()->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }
    }

    protected function requireBucketNotExists(string $bucket): void
    {
        if ($this->getStorage()->bucketExists($bucket)) {
            throw S3Exception::bucketAlreadyExists($bucket);
        }
    }

    protected function requireBucketEmpty(string $bucket): void
    {
        if (!$this->getStorage()->isBucketEmpty($bucket)) {
            throw S3Exception::bucketNotEmpty($bucket);
        }
    }
}