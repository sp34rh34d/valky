package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Cyberpunk 2077-inspired palette (24-bit ANSI truecolor). These are vars, not
// consts, so they can be blanked when color is unsupported.
//
// On Windows the readline library emulates ANSI itself and panics on truecolor
// sequences, so color is disabled there; NO_COLOR disables it everywhere.
var (
	cReset = "\x1b[0m"
	cBold  = "\x1b[1m"

	cYellow  = "\x1b[38;2;252;238;9m"   // signature neon yellow
	cCyan    = "\x1b[38;2;0;240;255m"   // electric cyan
	cMagenta = "\x1b[38;2;255;0;60m"    // hot red/magenta
	cGreen   = "\x1b[38;2;0;255;140m"   // online green
	cGray    = "\x1b[38;2;120;130;140m" // muted
	cBlue    = "\x1b[38;2;64;160;255m"
)

func init() {
	if runtime.GOOS == "windows" || os.Getenv("NO_COLOR") != "" {
		cReset, cBold = "", ""
		cYellow, cCyan, cMagenta, cGreen, cGray, cBlue = "", "", "", "", "", ""
	}
}

func paint(color, s string) string { return color + s + cReset }

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, w int) string {
	if n := w - runeLen(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

// renderTable prints a themed, aligned table. Padding is computed on the plain
// text and color is applied afterwards, so ANSI codes never break alignment.
// colorOf returns the color for a given (column, value) cell.
func renderTable(w io.Writer, headers []string, rows [][]string, colorOf func(col int, val string) string) {
	n := len(headers)
	width := make([]int, n)
	for i, h := range headers {
		width[i] = runeLen(h)
	}
	for _, r := range rows {
		for i := 0; i < n && i < len(r); i++ {
			if l := runeLen(r[i]); l > width[i] {
				width[i] = l
			}
		}
	}

	var sb strings.Builder
	// header
	for i, h := range headers {
		sb.WriteString(cBold + cYellow + pad(h, width[i]) + cReset)
		if i < n-1 {
			sb.WriteString("  ")
		}
	}
	fmt.Fprintln(w, sb.String())
	// separator
	sb.Reset()
	for i := 0; i < n; i++ {
		sb.WriteString(cMagenta + strings.Repeat("─", width[i]) + cReset)
		if i < n-1 {
			sb.WriteString("  ")
		}
	}
	fmt.Fprintln(w, sb.String())
	// rows
	for _, r := range rows {
		sb.Reset()
		for i := 0; i < n; i++ {
			val := ""
			if i < len(r) {
				val = r[i]
			}
			sb.WriteString(colorOf(i, val) + pad(val, width[i]) + cReset)
			if i < n-1 {
				sb.WriteString("  ")
			}
		}
		fmt.Fprintln(w, sb.String())
	}
}

// statusColor colors an online/offline marker.
func statusColor(v string) string {
	if v == "online" {
		return cGreen
	}
	return cGray
}

// modeLabel normalizes the agent operating mode for display.
func modeLabel(m string) string {
	switch m {
	case "tunnel", "proxy":
		return m
	default:
		return "?"
	}
}

// modeColor colors the operating mode (tunnel=green, proxy=yellow).
func modeColor(m string) string {
	switch m {
	case "tunnel":
		return cGreen
	case "proxy":
		return cYellow
	default:
		return cGray
	}
}

// author is injected at build time and shown subtly in the splash when set:
//
//	go build -ldflags "-X main.author=@spearh34d" ./cmd/valky
//
// It is empty by default, so a plain build shows no credit.
var author string

// authorTag returns the subtle credit suffix, or "" when no author was built in.
func authorTag() string {
	if author == "" {
		return ""
	}
	return paint(cGray, "  ·  "+author)
}

// banner is the Cyberpunk-styled splash shown when a console attaches.
func banner(ctrlAddr string) string {
	art := "" +
		"╔══════════════════════════════════════════════════╗\n" +
		"║  " + cBold + cYellow + "V A L K Y" + cReset + cCyan + "  ::  mesh control  ::  " + cMagenta + "night city" + cReset + cCyan + "   ║\n" +
		"╚══════════════════════════════════════════════════╝"
	tip := paint(cGray, "Tab = autocomplete   ↑/↓ = history   'help' = commands   'detach' = leave running")
	return "\n" + cCyan + art + cReset + "\n" +
		paint(cGray, "control "+ctrlAddr) + authorTag() + "\n" + tip + "\n"
}

// prompt is the themed input prompt for readline.
func prompt() string {
	return cMagenta + "valky" + cCyan + "❯ " + cReset
}
