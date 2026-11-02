package controller

import (
	"regexp"
	"strings"
)

// The Remote Control URL has no documented stdout API yet, so everything
// that depends on how Claude Code prints it is in this file: the pattern,
// the escape-sequence handling and FindURL. If the format changes, this is
// the one place to change.

var (
	urlPattern = regexp.MustCompile(`https://claude\.ai/code/\S+`)

	// OSC sequences: ESC ] ... terminated by BEL or ESC \. For OSC 8
	// hyperlinks (ESC ] 8 ; params ; URI ST) the URI is kept, separated by
	// spaces, in case the visible text isn't the URL itself.
	oscSeq = regexp.MustCompile(`\x1b\]([^\x07\x1b]*)(?:\x07|\x1b\\)`)
	// CSI sequences (colours, cursor movement) and other two-byte escapes.
	csiSeq = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]`)
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
	s = csiSeq.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, "\r", "\n")
}

// FindURL returns the first Remote Control URL in a controller log. The
// first, because Claude Code prints it at startup, before the agent does
// anything; a URL printed later may come from the agent (prompt injection
// can make it print anything) and must never replace the real one.
func FindURL(log []byte) (string, bool) {
	url := urlPattern.FindString(StripTerminal(string(log)))
	return url, url != ""
}

// lastLines returns up to n of the last non-empty lines of a log, with
// terminal escapes removed, for the "URL not found" message.
func lastLines(log []byte, n int) []string {
	var out []string
	for _, l := range strings.Split(StripTerminal(string(log)), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}
