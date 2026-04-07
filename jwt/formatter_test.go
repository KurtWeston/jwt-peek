package jwt

import (
	"strings"
	"testing"
	"time"
)

func TestFormatter_FormatCompact(t *testing.T) {
	token := &DecodedToken{
		Header: map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		Payload: map[string]interface{}{"sub": "1234567890", "name": "John Doe"},
		Valid:   true,
	}

	formatter := NewFormatter(false)
	result := formatter.Format(token, true, false, 3600)

	if !strings.Contains(result, "\"header\"") {
		t.Error("expected compact output to contain header")
	}

	if !strings.Contains(result, "\"payload\"") {
		t.Error("expected compact output to contain payload")
	}

	if !strings.Contains(result, "\"valid\":true") {
		t.Error("expected compact output to contain valid field")
	}
}

func TestFormatter_FormatCompact_WithError(t *testing.T) {
	token := &DecodedToken{
		Header:  map[string]interface{}{"alg": "HS256"},
		Payload: map[string]interface{}{"sub": "test"},
		Valid:   false,
		Error:   "signature verification failed",
	}

	formatter := NewFormatter(false)
	result := formatter.Format(token, true, false, 3600)

	if !strings.Contains(result, "\"error\"") {
		t.Error("expected compact output to contain error field")
	}

	if !strings.Contains(result, "signature verification failed") {
		t.Error("expected error message in output")
	}
}

func TestFormatter_FormatPretty(t *testing.T) {
	now := time.Now()
	iat := now.Add(-1 * time.Hour)
	exp := now.Add(2 * time.Hour)

	token := &DecodedToken{
		Header:    map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		Payload:   map[string]interface{}{"sub": "1234567890", "name": "John Doe"},
		Algorithm: "HS256",
		IssuedAt:  &iat,
		ExpiresAt: &exp,
		Valid:     true,
	}

	formatter := NewFormatter(false)
	result := formatter.Format(token, false, false, 3600)

	if !strings.Contains(result, "JWT Token Analysis") {
		t.Error("expected pretty output to contain title")
	}

	if !strings.Contains(result, "Algorithm: HS256") {
		t.Error("expected algorithm in output")
	}

	if !strings.Contains(result, "Issued At:") {
		t.Error("expected issued at in output")
	}

	if !strings.Contains(result, "Expires At:") {
		t.Error("expected expires at in output")
	}
}

func TestFormatter_FormatPretty_ExpiredToken(t *testing.T) {
	exp := time.Now().Add(-1 * time.Hour)

	token := &DecodedToken{
		Header:    map[string]interface{}{"alg": "HS256"},
		Payload:   map[string]interface{}{"sub": "test"},
		Algorithm: "HS256",
		ExpiresAt: &exp,
	}

	formatter := NewFormatter(false)
	result := formatter.Format(token, false, false, 3600)

	if !strings.Contains(result, "expired") {
		t.Error("expected expired message in output")
	}
}

func TestFormatter_FormatPretty_ExpiringSoon(t *testing.T) {
	exp := time.Now().Add(30 * time.Minute)

	token := &DecodedToken{
		Header:    map[string]interface{}{"alg": "HS256"},
		Payload:   map[string]interface{}{"sub": "test"},
		Algorithm: "HS256",
		ExpiresAt: &exp,
	}

	formatter := NewFormatter(false)
	result := formatter.Format(token, false, false, 3600)

	if !strings.Contains(result, "expires in") {
		t.Error("expected expiration warning in output")
	}
}

func TestFormatter_FormatPretty_WithRaw(t *testing.T) {
	token := &DecodedToken{
		Header:    map[string]interface{}{"alg": "HS256"},
		Payload:   map[string]interface{}{"sub": "test"},
		Algorithm: "HS256",
		RawParts:  []string{"header", "payload", "signature"},
	}

	formatter := NewFormatter(false)
	result := formatter.Format(token, false, true, 3600)

	if !strings.Contains(result, "Raw Segments:") {
		t.Error("expected raw segments section")
	}

	if !strings.Contains(result, "header") || !strings.Contains(result, "payload") {
		t.Error("expected raw parts in output")
	}
}

func TestFormatter_HumanDuration(t *testing.T) {
	formatter := NewFormatter(false)

	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m"},
		{2 * time.Hour, "2h"},
		{25 * time.Hour, "1d"},
	}

	for _, tt := range tests {
		result := formatter.humanDuration(tt.duration)
		if !strings.Contains(result, tt.expected[:1]) {
			t.Errorf("expected duration to contain %s, got %s", tt.expected, result)
		}
	}
}
