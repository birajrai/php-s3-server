# Rust S3 Server

S3-compatible object storage server in Rust.

## Run

```
cargo build --release
./target/release/s3-server
```

Port: 8000

## Operations

- Bucket: List, Create, Delete
- Object: Put, Get, Head, Delete
- Multipart: Create, UploadPart, Complete, Abort

## License

MIT