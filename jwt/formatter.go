package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Formatter struct {
	useColor bool
}

func NewFormatter(useColor bool) *Formatter {
	return &Formatter{useColor: useColor}
}

func (f *Formatter) Format(token *DecodedToken, compact, showRaw bool, expireThreshold int) string {
	if compact {
		return f.formatCompact(token)
	}
	return f.formatPretty(token, showRaw, expireThreshold)
}

func (f *Formatter) formatCompact(token *DecodedToken) string {
	data := map[string]interface{}{
		"header":  token.Header,
		"payload": token.Payload,
		"valid":   token.Valid,
	}
	if token.Error != "" {
		data["error"] = token.Error
	}
	b, _ := json.Marshal(data)
	return string(b)
}

func (f *Formatter) formatPretty(token *DecodedToken, showRaw bool, expireThreshold int) string {
	var sb strings.Builder

	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	if !f.useColor {
		red = fmt.Sprint
		yellow = fmt.Sprint
		green = fmt.Sprint
		cyan = fmt.Sprint
		bold = fmt.Sprint
	}

	sb.WriteString(bold("JWT Token Analysis\n"))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	sb.WriteString(bold("Algorithm: "))
	sb.WriteString(token.Algorithm + "\n")

	if token.IssuedAt != nil {
		sb.WriteString(bold("Issued At: "))
		sb.WriteString(fmt.Sprintf("%s (%s ago)\n", token.IssuedAt.Format(time.RFC3339), f.humanDuration(time.Since(*token.IssuedAt))))
	}

	if token.ExpiresAt != nil {
		sb.WriteString(bold("Expires At: "))
		now := time.Now()
		if token.ExpiresAt.Before(now) {
			sb.WriteString(red(fmt.Sprintf("%s (expired %s ago)\n", token.ExpiresAt.Format(time.RFC3339), f.humanDuration(now.Sub(*token.ExpiresAt)))))
		} else {
			timeUntil := token.ExpiresAt.Sub(now)
			if timeUntil.Seconds() < float64(expireThreshold) {
				sb.WriteString(yellow(fmt.Sprintf("%s (expires in %s)\n", token.ExpiresAt.Format(time.RFC3339), f.humanDuration(timeUntil))))
			} else {
				sb.WriteString(green(fmt.Sprintf("%s (expires in %s)\n", token.ExpiresAt.Format(time.RFC3339), f.humanDuration(timeUntil))))
			}
		}
	}

	if token.NotBefore != nil {
		sb.WriteString(bold("Not Before: "))
		sb.WriteString(token.NotBefore.Format(time.RFC3339) + "\n")
	}

	if token.Error != "" {
		sb.WriteString(bold("\nSignature Validation: "))
		sb.WriteString(red("INVALID\n"))
		sb.WriteString(bold("Error: "))
		sb.WriteString(red(token.Error) + "\n")
	} else if token.Valid {
		sb.WriteString(bold("\nSignature Validation: "))
		sb.WriteString(green("VALID\n"))
	}

	sb.WriteString("\n" + bold("Header:\n"))
	sb.WriteString(f.formatJSON(token.Header, cyan))

	sb.WriteString("\n" + bold("Payload:\n"))
	sb.WriteString(f.formatJSON(token.Payload, cyan))

	if showRaw {
		sb.WriteString("\n" + bold("Raw Segments:\n"))
		sb.WriteString(fmt.Sprintf("Header:    %s\n", token.RawParts[0]))
		sb.WriteString(fmt.Sprintf("Payload:   %s\n", token.RawParts[1]))
		sb.WriteString(fmt.Sprintf("Signature: %s\n", token.RawParts[2]))
	}

	return sb.String()
}

func (f *Formatter) formatJSON(data map[string]interface{}, colorFunc func(...interface{}) string) string {
	b, _ := json.MarshalIndent(data, "", "  ")
	if f.useColor {
		return colorFunc(string(b))
	}
	return string(b)
}

func (f *Formatter) humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
