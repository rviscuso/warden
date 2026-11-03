package controller

import (
	"strings"
	"testing"
)

func TestFindURL(t *testing.T) {
	cases := map[string]struct {
		log, want string
	}{
		"plain":       {"Starting\nRemote Control: https://claude.ai/code/session_01ABC\n", "https://claude.ai/code/session_01ABC"},
		"coloured":    {"\x1b[1m\x1b[36mhttps://claude.ai/code/session_01ABC\x1b[0m\r\n", "https://claude.ai/code/session_01ABC"},
		"first wins":  {"https://claude.ai/code/real\nagent output: https://claude.ai/code/injected\n", "https://claude.ai/code/real"},
		"osc8 link":   {"open \x1b]8;;https://claude.ai/code/session_X\x1b\\this link\x1b]8;;\x1b\\ now", "https://claude.ai/code/session_X"},
		"osc8 bel":    {"\x1b]8;;https://claude.ai/code/session_Y\x07here\x1b]8;;\x07", "https://claude.ai/code/session_Y"},
		"title osc":   {"\x1b]0;claude\x07https://claude.ai/code/s1 ", "https://claude.ai/code/s1"},
		"cursor move": {"\x1b[2K\x1b[1Ghttps://claude.ai/code/s2\x1b[K", "https://claude.ai/code/s2"},
	}
	for name, c := range cases {
		got, ok := FindURL([]byte(c.log))
		if !ok || got != c.want {
			t.Errorf("%s: got %q %v, want %q", name, got, ok, c.want)
		}
	}
}

func TestFindURLNone(t *testing.T) {
	for _, log := range []string{
		"",
		"Please log in: https://claude.ai/login\n",
		"https://claude.ai/codex/x\n",
		"https://evil.example/https:/claude.ai/code/x",
		"http://claude.ai/code/x\n",
		"https://claude.ai/code/\n",
	} {
		if got, ok := FindURL([]byte(log)); ok {
			t.Errorf("%q: found %q", log, got)
		}
	}
}

func TestLastLines(t *testing.T) {
	log := "a\n\n\x1b[31mb\x1b[0m\nc\r\nd\n"
	if got := strings.Join(lastLines([]byte(log), 3), "|"); got != "b|c|d" {
		t.Fatalf("got %q", got)
	}
}

// TestStripTerminalKeepsSpaces: TUIs draw spaces as cursor movement. The
// first live run showed "WelcometoClaudeCodev2.1.309" before this fix; a
// URL followed by such a gap would have absorbed the next word.
func TestStripTerminalKeepsSpaces(t *testing.T) {
	cases := map[string]string{
		"Welcome\x1b[1Cto\x1b[1CClaude\x1b[1CCode": "Welcome to Claude Code",
		"a\x1b[3Cb":                      "a   b",
		"a\x1b[Cb":                       "a b", // no count: one column
		"\x1b[1mbold\x1b[0m\x1b[1Cplain": "bold plain",
		"x\x1b[2Ky":                      "x y", // erase: a space
		"line\x1b[1;5Hnext":              "line next",
		"a\x1b[99999Cb":                  "a" + strings.Repeat(" ", 256) + "b", // capped
	}
	for in, want := range cases {
		if got := StripTerminal(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	log := "Remote Control:\x1b[1Chttps://claude.ai/code/session_A\x1b[1CPress\x1b[1Center\n"
	if got, _ := FindURL([]byte(log)); got != "https://claude.ai/code/session_A" {
		t.Fatalf("FindURL = %q: the next word was glued on", got)
	}
}
