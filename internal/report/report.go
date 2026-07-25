// Package report provides output formatters for SubReaper scan results.
package report

import (
	"fmt"
	"io"

	"github.com/MrEx-Right/SubReaper/internal/models"
)

// Reporter is the interface implemented by all output formatters.
type Reporter interface {
	// Write serializes the ScanResult to the given writer.
	Write(w io.Writer, result *models.ScanResult) error
}

// New returns a Reporter for the given format string.
// Valid formats: "terminal", "json", "markdown", "html".
func New(format string, noColor bool) (Reporter, error) {
	switch format {
	case "terminal", "":
		return &TerminalReporter{NoColor: noColor}, nil
	case "json":
		return &JSONReporter{}, nil
	case "markdown":
		return &MarkdownReporter{}, nil
	case "html":
		return &HTMLReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (valid: terminal, json, markdown, html)", format)
	}
}
