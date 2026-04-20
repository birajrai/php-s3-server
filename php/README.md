# PHP S3 Server

S3-compatible object storage server in PHP.

## Setup

Upload to a web server. Configure `.config.ini`:

```ini
[keys.key1]
secret_key=your-secret-key
allowed_buckets=bucket1,bucket2
file_max_size=10240
```

## Operations

- Bucket: List, Create, Delete
- Object: Put, Get, Head, Delete, Copy
- Multipart: Create, UploadPart, Complete, Abort

## License

MIT