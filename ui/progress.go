package ui

import (
	"fmt"
	"io"
	"time"

	"github.com/schollz/progressbar/v3"
)

// ScanBar wraps schollz/progressbar with live domain + findings display.
type ScanBar struct {
	bar     *progressbar.ProgressBar
	w       io.Writer
	total   int
	showBar bool
	start   time.Time
}

// NewScanBar creates a styled progress bar for domain scanning.
// If showBar is false all calls are no-ops (silent / JSON mode).
func NewScanBar(w io.Writer, total int, showBar bool) *ScanBar {
	sb := &ScanBar{w: w, total: total, showBar: showBar, start: time.Now()}
	if !showBar {
		return sb
	}

	sb.bar = progressbar.NewOptions(total,
		progressbar.OptionSetWriter(w),
		progressbar.OptionSetDescription("  Scanning"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "▓",
			SaucerPadding: "░",
			BarStart:      "│",
			BarEnd:        "│",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(36),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetRenderBlankState(true),
	)
	return sb
}

// Tick advances the bar by one and updates the description with live stats.
func (sb *ScanBar) Tick(domain string, scanned, findings int) {
	if !sb.showBar || sb.bar == nil {
		return
	}

	elapsed := time.Since(sb.start)
	var eta string
	if scanned > 0 {
		perDomain := elapsed / time.Duration(scanned)
		remaining := time.Duration(sb.total-scanned) * perDomain
		eta = fmtDuration(remaining)
	} else {
		eta = "?"
	}

	desc := fmt.Sprintf("  [cyan][bold]Scanning[reset] [yellow]%-30s[reset] │ [green]%d findings[reset] │ ETA %s",
		truncate(domain, 30), findings, eta)
	sb.bar.Describe(desc)
	_ = sb.bar.Add(1)
}

// Finish completes and clears the bar.
func (sb *ScanBar) Finish() {
	if sb.showBar && sb.bar != nil {
		_ = sb.bar.Finish()
	}
}

// truncate shortens a string to max n runes, adding "…" if needed.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

// fmtDuration formats a duration as "m:ss".
func fmtDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%d:%02d", m, s)
}
