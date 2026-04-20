# S3 Compatible Server

S3-compatible object storage server in PHP, Go, and Rust.

## Implementations

| Language | Directory |
|----------|-----------|
| PHP | `php/` |
| Go | `go/` |
| Rust | `rust/` |

## Usage

### PHP
Upload to a web server, configure `.config.ini`.

### Go
```
cd go
go build -o s3server.exe
./s3server.exe
```

### Rust
```
cd rust
cargo build --release
./target/release/s3-server
```

Default port: 8000

## License

MIT