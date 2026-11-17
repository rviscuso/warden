package termsafe

import (
	"strings"
	"testing"
)

func filter(chunks ...string) string {
	var b strings.Builder
	w := &Writer{W: &b}
	for _, c := range chunks {
		w.Write([]byte(c))
	}
	w.Flush()
	return b.String()
}

func TestWriter(t *testing.T) {
	for in, want := range map[string]string{
		"#5 [base 2/2] RUN apt-get update\n":    "#5 [base 2/2] RUN apt-get update\n",
		"tab\there\r\n":                         "tab\there\n",
		"\x1b[31mred\x1b[0m\n":                  "[31mred[0m\n",
		"\x1b]52;c;aGVsbG8=\x07clip":            "]52;c;aGVsbG8=clip",
		"\x1b]0;title\x1b\\":                    "]0;title\\",
		"over\rwrite":                           "overwrite",
		"bell\x07 del\x7f bs\x08":               "bell del bs",
		"c1 csi \xc2\x9b31m":                    "c1 csi 31m",
		"c1 osc \xc2\x9d0;t\xc2\x9c":            "c1 osc 0;t",
		"Ünïcödé ✓ é (\xc3\xa9) ¢ (\xc2\xa2)\n": "Ünïcödé ✓ é (é) ¢ (¢)\n",
	} {
		if got := filter(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// A C1 control split across writes is still removed; a lone 0xC2 at the
// end is written by Flush.
func TestWriterSplit(t *testing.T) {
	if got := filter("a\xc2", "\x9bb"); got != "ab" {
		t.Errorf("split C1: %q", got)
	}
	if got := filter("a\xc2", "\xa2b"); got != "a\xc2\xa2b" {
		t.Errorf("split ¢: %q", got)
	}
	if got := filter("end\xc2"); got != "end\xc2" {
		t.Errorf("trailing: %q", got)
	}
}
