// Package ui — LiveDisplay provides a multi-line animated stage panel
// for the brute command (crt.sh → wordlist → permutation → scan).
package ui

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Stage represents one phase of the brute pipeline.
type Stage struct {
	Label   string // e.g. "crt.sh"
	spinner *Spinner
}

// LiveDisplay draws a bordered stage panel for multi-phase operations.
type LiveDisplay struct {
	mu      sync.Mutex
	w       io.Writer
	stages  []*Stage
	noColor bool
}

// NewLiveDisplay creates a LiveDisplay for brute scanning.
// noColor suppresses ANSI color codes.
func NewLiveDisplay(w io.Writer, noColor bool) *LiveDisplay {
	if noColor {
		color.NoColor = true
	}
	return &LiveDisplay{w: w, noColor: noColor}
}

// Header prints the top bar of the live panel.
func (ld *LiveDisplay) Header(target string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)

	fmt.Fprintln(ld.w)
	cyan.Fprintf(ld.w, "  ┌─────────────────────────────────────────────────────┐\n")
	cyan.Fprintf(ld.w, "  │  ")
	color.New(color.Bold).Fprintf(ld.w, "%-50s", "SubReaper — Discovery Pipeline")
	cyan.Fprintf(ld.w, " │\n")
	cyan.Fprintf(ld.w, "  │  ")
	dim.Fprintf(ld.w, "Target: %-44s", target)
	cyan.Fprintf(ld.w, " │\n")
	cyan.Fprintf(ld.w, "  └─────────────────────────────────────────────────────┘\n")
	fmt.Fprintln(ld.w)
}

// StartStage begins an animated stage and returns a handle to it.
// prefix is padded to 10 chars for alignment, e.g. "crt.sh", "wordlist".
func (ld *LiveDisplay) StartStage(label, msg string) *Stage {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	col := stageColor(len(ld.stages))
	prefix := stagePrefix(label)
	sp := NewSpinner(ld.w, prefix, msg, col)

	stage := &Stage{Label: label, spinner: sp}
	ld.stages = append(ld.stages, stage)

	sp.Start()
	return stage
}

// DoneStage stops the spinner for a stage with a success or failure message.
func (ld *LiveDisplay) DoneStage(s *Stage, success bool, msg string) {
	if s == nil || s.spinner == nil {
		return
	}
	s.spinner.Stop(success, msg)
}

// SkipStage prints a dimmed skipped line for an unused stage.
func (ld *LiveDisplay) SkipStage(label, msg string) {
	ld.mu.Lock()
	col := stageColor(len(ld.stages))
	prefix := stagePrefix(label)
	sp := NewSpinner(ld.w, prefix, msg, col)
	ld.mu.Unlock()
	sp.Skip(msg)
}

// Footer prints a summary separator before the scan begins.
func (ld *LiveDisplay) Footer(total int) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	fmt.Fprintln(ld.w)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Fprintf(ld.w, "  ──────────────────────────────────────────────────────\n")
	dim.Fprintf(ld.w, "  Scanning %d unique subdomains through full pipeline…\n", total)
	cyan.Fprintf(ld.w, "  ──────────────────────────────────────────────────────\n")
	fmt.Fprintln(ld.w)
}

// PrintScanComplete prints an animated "scan complete" flash line.
func PrintScanComplete(w io.Writer, noColor bool, findings int, dur string) {
	if noColor {
		fmt.Fprintf(w, "\n  ✓ Scan complete in %s — %d finding(s)\n\n", dur, findings)
		return
	}

	frames := []string{"·", "··", "···", "····", "·····"}
	for _, f := range frames {
		color.New(color.FgCyan).Fprintf(w, "\r  Finalizing %s", f)
		time.Sleep(60 * time.Millisecond)
	}
	fmt.Fprintf(w, "\r")

	icon := color.New(color.FgGreen, color.Bold).Sprint("✓")
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s ", icon)
	bold.Fprintf(w, "Scan complete")
	dim.Fprintf(w, " in %s", dur)
	if findings > 0 {
		color.New(color.FgYellow, color.Bold).Fprintf(w, " — %d finding(s)", findings)
	} else {
		color.New(color.FgGreen).Fprintf(w, " — no findings")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
}

// stagePrefix formats a stage label into a fixed-width colored bracket tag.
func stagePrefix(label string) string {
	padded := fmt.Sprintf("%-8s", label)
	return color.New(color.Faint).Sprint("[") +
		color.New(color.FgCyan, color.Bold).Sprint(padded) +
		color.New(color.Faint).Sprint("]")
}

// stageColor returns a rotating color for stage spinners.
func stageColor(idx int) *color.Color {
	palette := []*color.Color{
		color.New(color.FgCyan),
		color.New(color.FgMagenta),
		color.New(color.FgYellow),
		color.New(color.FgGreen),
	}
	return palette[idx%len(palette)]
}
