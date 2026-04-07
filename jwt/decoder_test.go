package jwt

import (
	"testing"
	"time"
)

func TestDecoder_Decode_ValidToken(t *testing.T) {
	// Valid HS256 token: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1916239022}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	decoder := NewDecoder()
	result, err := decoder.Decode(token, "")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Algorithm != "HS256" {
		t.Errorf("expected algorithm HS256, got %s", result.Algorithm)
	}

	if result.Payload["sub"] != "1234567890" {
		t.Errorf("expected sub claim 1234567890, got %v", result.Payload["sub"])
	}

	if result.IssuedAt == nil {
		t.Error("expected IssuedAt to be set")
	} else if result.IssuedAt.Unix() != 1516239022 {
		t.Errorf("expected iat 1516239022, got %d", result.IssuedAt.Unix())
	}

	if result.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
}

func TestDecoder_Decode_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"single part", "eyJhbGciOiJIUzI1NiJ9"},
		{"two parts", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0"},
		{"four parts", "a.b.c.d"},
	}

	decoder := NewDecoder()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decoder.Decode(tt.token, "")
			if err == nil {
				t.Error("expected error for invalid token format")
			}
		})
	}
}

func TestDecoder_Decode_InvalidBase64(t *testing.T) {
	token := "invalid!base64.eyJzdWIiOiIxMjM0In0.signature"
	decoder := NewDecoder()

	_, err := decoder.Decode(token, "")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecoder_Decode_InvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON
	token := "bm90anNvbg.eyJzdWIiOiIxMjM0In0.sig"
	decoder := NewDecoder()

	_, err := decoder.Decode(token, "")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecoder_Decode_WithValidSecret(t *testing.T) {
	// Token signed with secret "your-256-bit-secret"
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	secret := "your-256-bit-secret"

	decoder := NewDecoder()
	result, err := decoder.Decode(token, secret)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid signature, got error: %s", result.Error)
	}
}

func TestDecoder_Decode_WithInvalidSecret(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	secret := "wrong-secret"

	decoder := NewDecoder()
	result, err := decoder.Decode(token, secret)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Valid {
		t.Error("expected invalid signature with wrong secret")
	}

	if result.Error == "" {
		t.Error("expected error message for invalid signature")
	}
}

func TestDecoder_Decode_AllTimeFields(t *testing.T) {
	// Token with iat, exp, nbf
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTkxNjIzOTAyMiwibmJmIjoxNTE2MjM5MDIyfQ.4Adcj0vt1z3hFmXJIJXfRnMbH5FXrJ-_FfqhJZ5qBnQ"

	decoder := NewDecoder()
	result, err := decoder.Decode(token, "")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.IssuedAt == nil {
		t.Error("expected IssuedAt to be set")
	}

	if result.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}

	if result.NotBefore == nil {
		t.Error("expected NotBefore to be set")
	}

	expectedTime := time.Unix(1516239022, 0)
	if !result.IssuedAt.Equal(expectedTime) {
		t.Errorf("expected IssuedAt %v, got %v", expectedTime, result.IssuedAt)
	}
}
