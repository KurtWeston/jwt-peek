# jwt-peek

Decode and inspect JWT tokens from the command line with signature validation and expiration warnings

## Features

- Decode JWT tokens without signature verification to inspect header and payload
- Validate JWT signatures using provided secrets (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512)
- Read tokens from command line arguments, stdin, files, or clipboard
- Pretty-print JSON claims with syntax highlighting and proper indentation
- Highlight expired tokens in red with time-since-expiration
- Warn about tokens expiring soon (within configurable threshold, default 1 hour)
- Display token metadata: algorithm, issued at, expires at, not before
- Show raw base64 segments for debugging encoding issues
- Support for standard claims (iss, sub, aud, exp, nbf, iat, jti) with human-readable labels
- Colorized output with color auto-detection for non-TTY pipes
- Compact mode for scripting (JSON output only)
- Verify token structure without secret (check for valid base64 and JSON)
- Display token age and time until expiration in human-readable format

## How to Use

Use this project when you need to:

- Quickly solve problems related to jwt-peek
- Integrate go functionality into your workflow
- Learn how go handles common patterns

## Installation

```bash
# Clone the repository
git clone https://github.com/KurtWeston/jwt-peek.git
cd jwt-peek

# Install dependencies
go build
```

## Usage

```bash
./main
```

## Built With

- go

## Dependencies

- `github.com/golang-jwt/jwt/v5`
- `github.com/fatih/color`
- `github.com/spf13/cobra`
- `golang.org/x/term`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
