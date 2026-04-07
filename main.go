package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yourusername/jwt-peek/jwt"
	"golang.org/x/term"
)

var (
	secret          string
	compact         bool
	showRaw         bool
	noColor         bool
	expireThreshold int
)

var rootCmd = &cobra.Command{
	Use:   "jwt-peek [token]",
	Short: "Decode and inspect JWT tokens",
	Long:  "Decode JWT tokens from command line, stdin, or files with signature validation and expiration warnings",
	Args:  cobra.MaximumNArgs(1),
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVarP(&secret, "secret", "s", "", "Secret key for signature validation")
	rootCmd.Flags().BoolVarP(&compact, "compact", "c", false, "Compact JSON output for scripting")
	rootCmd.Flags().BoolVarP(&showRaw, "raw", "r", false, "Show raw base64 segments")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.Flags().IntVarP(&expireThreshold, "expire-threshold", "t", 3600, "Expiration warning threshold in seconds")
}

func run(cmd *cobra.Command, args []string) error {
	var tokenStr string

	if len(args) > 0 {
		tokenStr = args[0]
	} else {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("no token provided. Pass as argument or pipe via stdin")
		}
		reader := bufio.NewReader(os.Stdin)
		input, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		tokenStr = strings.TrimSpace(string(input))
	}

	if tokenStr == "" {
		return fmt.Errorf("empty token provided")
	}

	decoder := jwt.NewDecoder()
	result, err := decoder.Decode(tokenStr, secret)
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}

	formatter := jwt.NewFormatter(!noColor && term.IsTerminal(int(os.Stdout.Fd())))
	output := formatter.Format(result, compact, showRaw, expireThreshold)
	fmt.Println(output)

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
