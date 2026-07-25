// Package ui provides terminal animation and progress display components.
package ui

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Spinner frames using Braille characters for a smooth animation.
var spinnerFrames = []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}

// Spinner is a terminal spinner that displays an animated indicator.
type Spinner struct {
	mu      sync.Mutex
	w       io.Writer
	label   string
	prefix  string
	col     *color.Color
	frame   int
	running bool
	done    chan struct{}
}

// NewSpinner creates a new Spinner writing to w.
// prefix is a fixed left-side label (e.g. "[ crt.sh  ]"), label is the message.
func NewSpinner(w io.Writer, prefix, label string, col *color.Color) *Spinner {
	return &Spinner{
		w:      w,
		prefix: prefix,
		label:  label,
		col:    col,
		done:   make(chan struct{}),
	}
}

// SetLabel updates the spinner message while running.
func (s *Spinner) SetLabel(label string) {
	s.mu.Lock()
	s.label = label
	s.mu.Unlock()
}

// Start begins the spinner animation in a background goroutine.
func (s *Spinner) Start() {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.mu.Lock()
				frame := spinnerFrames[s.frame%len(spinnerFrames)]
				s.frame++
				prefix := s.prefix
				label := s.label
				col := s.col
				s.mu.Unlock()

				col.Fprintf(s.w, "\r  %s %s %s   ", prefix, frame, label)
			}
		}
	}()
}

// Stop halts the animation and prints a final status line.
// success=true prints a ✓ (green), false prints ✗ (red).
func (s *Spinner) Stop(success bool, finalMsg string) {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	// Small pause so the last frame is visible before overwriting
	time.Sleep(40 * time.Millisecond)

	if success {
		icon := color.New(color.FgGreen, color.Bold).Sprint("✓")
		fmt.Fprintf(s.w, "\r  %s %s %s\n", s.prefix, icon, finalMsg)
	} else {
		icon := color.New(color.FgRed, color.Bold).Sprint("✗")
		fmt.Fprintf(s.w, "\r  %s %s %s\n", s.prefix, icon, finalMsg)
	}
}

// Skip prints a dimmed skip line (aşama atlandı).
func (s *Spinner) Skip(msg string) {
	s.mu.Lock()
	if s.running {
		s.running = false
		close(s.done)
	}
	s.mu.Unlock()
	dim := color.New(color.Faint)
	fmt.Fprintf(s.w, "\r  %s %s %s\n", s.prefix, dim.Sprint("-"), dim.Sprint(msg))
}
