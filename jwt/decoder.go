package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type DecodedToken struct {
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	RawParts  []string
	Valid     bool
	Error     string
	Algorithm string
	IssuedAt  *time.Time
	ExpiresAt *time.Time
	NotBefore *time.Time
}

type Decoder struct{}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Decode(tokenStr, secret string) (*DecodedToken, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	result := &DecodedToken{
		RawParts: parts,
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if err := json.Unmarshal(headerBytes, &result.Header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &result.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	result.Signature = parts[2]

	if alg, ok := result.Header["alg"].(string); ok {
		result.Algorithm = alg
	}

	if iat, ok := result.Payload["iat"].(float64); ok {
		t := time.Unix(int64(iat), 0)
		result.IssuedAt = &t
	}

	if exp, ok := result.Payload["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		result.ExpiresAt = &t
	}

	if nbf, ok := result.Payload["nbf"].(float64); ok {
		t := time.Unix(int64(nbf), 0)
		result.NotBefore = &t
	}

	if secret != "" {
		result.Valid, result.Error = d.validateSignature(tokenStr, secret)
	}

	return result, nil
}

func (d *Decoder) validateSignature(tokenStr, secret string) (bool, string) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return []byte(secret), nil
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			return jwt.ParseRSAPublicKeyFromPEM([]byte(secret))
		default:
			return nil, fmt.Errorf("unsupported signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		return false, err.Error()
	}

	return token.Valid, ""
}
