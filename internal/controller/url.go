package controller

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/rviscuso/warden/internal/state"
	"github.com/rviscuso/warden/internal/termsafe"
)

// The Remote Control URL has no documented stdout API yet, so everything
// that depends on how Claude Code prints it is in this file: the pattern,
// the escape-sequence handling and FindURL. If the format changes, this is
// the one place to change.

var (
	// urlCandidate finds where a URL starts and how far it runs. Whether it
	// is accepted is state.RemoteControlURL's decision, not this pattern's.
	urlCandidate = regexp.MustCompile(`https://claude\.ai/code/\S+`)

	// OSC sequences: ESC ] ... terminated by BEL or ESC \. For OSC 8
	// hyperlinks (ESC ] 8 ; params ; URI ST) the URI is kept, separated by
	// spaces, in case the visible text isn't the URL itself.
	oscSeq = regexp.MustCompile(`\x1b\]([^\x07\x1b]*)(?:\x07|\x1b\\)`)
	// CSI sequences: ESC [ params intermediates final. Colours (final m) are
	// removed; cursor movement and erasing stand for space a TUI skipped, so
	// they become spaces and words, and a URL's end, stay apart.
	csiSeq = regexp.MustCompile(`\x1b\[([0-?]*)[ -/]*([@-~])`)
	// Other two-byte escapes.
	escSeq = regexp.MustCompile(`\x1b[@-Z\\-_]`)
)

// StripTerminal removes terminal escape sequences from a TTY log, keeping
// OSC 8 hyperlink targets, and turns carriage returns into newlines.
func StripTerminal(s string) string {
	s = oscSeq.ReplaceAllStringFunc(s, func(m string) string {
		body := oscSeq.FindStringSubmatch(m)[1]
		if rest, ok := strings.CutPrefix(body, "8;"); ok {
			if _, uri, ok := strings.Cut(rest, ";"); ok && uri != "" {
				return " " + uri + " "
			}
		}
		return ""
	})
	s = csiSeq.ReplaceAllStringFunc(s, func(m string) string {
		sub := csiSeq.FindStringSubmatch(m)
		switch sub[2] {
		case "m": // colours and styles
			return ""
		case "C": // cursor forward n columns: n spaces
			n, err := strconv.Atoi(sub[1])
			if err != nil || n < 1 {
				n = 1
			}
			return strings.Repeat(" ", min(n, 256))
		}
		return " " // any other movement or erase
	})
	s = escSeq.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, "\r", "\n")
}

// FindURL returns the first Remote Control URL in a controller log. The
// first, because Claude Code prints it at startup, before the agent does
// anything; a URL printed later may come from the agent (prompt injection
// can make it print anything) and must never replace the real one.
//
// The first candidate must match state.RemoteControlURL in full: only URL
// characters, bounded length. One that doesn't (a control character or the
// rest of an escape sequence glued to it) is refused, and no later URL is
// taken in its place: that would let a crafted first URL hand the choice
// to whatever is printed next.
func FindURL(log []byte) (string, bool) {
	url := urlCandidate.FindString(StripTerminal(string(log)))
	if !state.RemoteControlURL.MatchString(url) {
		return "", false
	}
	return url, true
}

// lastLines returns up to n of the last non-empty lines of a log, for the
// "URL not found" message: terminal escapes removed, then every control
// character StripTerminal left (it is one pass, and a crafted sequence can
// survive it), since the lines are printed on the user's terminal.
func lastLines(log []byte, n int) []string {
	var out []string
	for _, l := range strings.Split(termsafe.String(StripTerminal(string(log))), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}
