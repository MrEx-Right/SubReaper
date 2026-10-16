package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
	"golang.org/x/term"
)

// Version is shown in the banner. The cmd package sets it at startup.
var Version = "dev"

// scytheArt is a scythe drawn beside the title, the same height as it: a
// curved blade at the top whose tip points down-left, and a diagonal handle.
var scytheArt = [...]string{
	"       ▄▄▄▄▄▄▄▄  ",
	"   ▄▄██▀▀▀▀▀▀▀██▄",
	" ▄█▀▀         ██▀",
	"▀▀           ▐█▌ ",
	"            ▐█▌  ",
	"           ▐█▌   ",
}

// handleFromColumn: from the third row down, runes at or right of this
// column belong to the handle; everything else is blade.
const handleFromColumn = 11

// titleArt spells SUBREAPER in block letters. The first subColumns runes of
// each row are "SUB", the rest are "REAPER".
var titleArt = [...]string{
	"███████╗██╗   ██╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ ",
	"██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗",
	"███████╗██║   ██║██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝",
	"╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗",
	"███████║╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║",
	"╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝",
}

const (
	subColumns = 25
	indent     = "  "
	artGap     = "   "
)

// 256-color palette. The scythe blade is polished steel and its handle dark
// wood. In the title, "SUB" fades from white to steel grey and "REAPER" from
// bright red to blood red; box-drawing "shadow" strokes use a darker shade so
// letters look raised.
var (
	bladeFace   = [...]int{255, 253, 250, 247, 247, 247}
	handleFace  = [...]int{137, 137, 137, 130, 94, 94}
	subFace     = [...]int{255, 254, 252, 250, 248, 246}
	reaperFace  = [...]int{196, 196, 160, 160, 124, 124}
	subShadow   = 240
	reaperShade = 88
)

// Layout widths: scythe beside the title, or the title alone.
var (
	titleWidth = utf8.RuneCountInString(titleArt[0])
	artWidth   = utf8.RuneCountInString(scytheArt[0])
	wideWidth  = len(indent) + artWidth + len(artGap) + titleWidth
	tallWidth  = len(indent) + titleWidth
)

// PrintBanner prints the SubReaper banner, picking the richest layout that
// fits the terminal. Output that is not a terminal gets the plain title.
func PrintBanner(w io.Writer, noColor bool) {
	if noColor {
		color.NoColor = true
	}
	plain := color.NoColor // also true when the output is not a terminal
	cols := terminalWidth(w)

	var lines []string
	switch {
	case cols >= wideWidth:
		lines = wideLayout(plain)
	case cols >= tallWidth:
		lines = titleOnly(plain)
	case cols > 0:
		lines = []string{indent + paint(plain, 196, "SubReaper") + " " + paint(plain, 245, versionLabel()) + "  " + paint(plain, 250, "Subdomain Takeover Scanner")}
	default:
		lines = titleOnly(plain)
	}

	fmt.Fprintln(w)
	for _, l := range lines {
		fmt.Fprintln(w, strings.TrimRight(l, " "))
	}
	fmt.Fprintln(w)
}

// wideLayout puts the scythe to the left of the title, with the tagline
// lines aligned under the title.
func wideLayout(plain bool) []string {
	var lines []string
	for row := range titleArt {
		lines = append(lines, indent+scytheRow(plain, row)+artGap+titleRow(plain, row))
	}
	pad := indent + strings.Repeat(" ", artWidth) + artGap
	return append(lines, pad+taglineRow(plain), pad+ruleRow(plain), pad+footerRow(plain))
}

// titleOnly is the title, tagline, rule and footer without the scythe.
func titleOnly(plain bool) []string {
	var lines []string
	for row := range titleArt {
		lines = append(lines, indent+titleRow(plain, row))
	}
	return append(lines, indent+taglineRow(plain), indent+ruleRow(plain), indent+footerRow(plain))
}

func scytheRow(plain bool, row int) string {
	if plain {
		return scytheArt[row]
	}
	var sb strings.Builder
	cur := -1
	for col, r := range []rune(scytheArt[row]) {
		c := bladeFace[row]
		if row >= 2 && col >= handleFromColumn {
			c = handleFace[row]
		}
		if c != cur {
			fmt.Fprintf(&sb, "\x1b[38;5;%dm", c)
			cur = c
		}
		sb.WriteRune(r)
	}
	sb.WriteString("\x1b[0m")
	return sb.String()
}

func titleRow(plain bool, row int) string {
	if plain {
		return titleArt[row]
	}
	var sb strings.Builder
	cur := -1
	for col, r := range []rune(titleArt[row]) {
		c := titleShade(row, col, r)
		if c != cur {
			fmt.Fprintf(&sb, "\x1b[38;5;%dm", c)
			cur = c
		}
		sb.WriteRune(r)
	}
	sb.WriteString("\x1b[0m")
	return sb.String()
}

// titleShade returns the 256-color code for the rune at row/col of the title.
func titleShade(row, col int, r rune) int {
	isShadow := r != '█'
	if col < subColumns {
		if isShadow {
			return subShadow
		}
		return subFace[row]
	}
	if isShadow {
		return reaperShade
	}
	return reaperFace[row]
}

func taglineRow(plain bool) string {
	tagline := "Subdomain Takeover Scanner"
	ver := versionLabel()
	gap := titleWidth - utf8.RuneCountInString(tagline) - utf8.RuneCountInString(ver)
	if gap < 1 {
		gap = 1
	}
	if plain {
		return tagline + strings.Repeat(" ", gap) + ver
	}
	return "\x1b[1m" + tagline + "\x1b[0m" + strings.Repeat(" ", gap) + paint(false, 196, ver)
}

func ruleRow(plain bool) string {
	return paint(plain, reaperShade, strings.Repeat("─", titleWidth))
}

func footerRow(plain bool) string {
	return paint(plain, 245, "github.com/MrEx-Right/SubReaper  ·  authorized testing only")
}

func versionLabel() string {
	return "v" + strings.TrimPrefix(Version, "v")
}

// paint wraps s in a 256-color foreground code unless plain is set.
func paint(plain bool, c int, s string) string {
	if plain {
		return s
	}
	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", c, s)
}

// terminalWidth returns the column count of w, or 0 if w is not a terminal.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return cols
}
