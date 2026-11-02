package controller

import (
	"strings"
	"testing"
)

func TestDiffEqual(t *testing.T) {
	if d := Diff([]byte("a\nb\n"), []byte("a\nb\n")); d != "" {
		t.Fatalf("equal inputs: %q", d)
	}
}

func TestDiffChange(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"
	b := "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\n"
	want := "--- applied\n+++ new\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"
	if d := Diff([]byte(a), []byte(b)); d != want {
		t.Fatalf("got:\n%s\nwant:\n%s", d, want)
	}
}

func TestDiffSeparateHunks(t *testing.T) {
	var a, b []string
	for i := 0; i < 30; i++ {
		a = append(a, "same")
		b = append(b, "same")
	}
	a[2], b[2] = "old top", "new top"
	a[25], b[25] = "old bottom", "new bottom"
	d := Diff([]byte(strings.Join(a, "\n")+"\n"), []byte(strings.Join(b, "\n")+"\n"))
	if strings.Count(d, "@@ -") != 2 {
		t.Fatalf("want two hunks:\n%s", d)
	}
	for _, s := range []string{"-old top", "+new top", "-old bottom", "+new bottom"} {
		if !strings.Contains(d, s+"\n") {
			t.Errorf("missing %q:\n%s", s, d)
		}
	}
}

func TestDiffAddRemove(t *testing.T) {
	d := Diff([]byte("a\nb\n"), []byte("a\nb\nc\n"))
	if !strings.Contains(d, "+c\n") || strings.Contains(d, "-a") {
		t.Fatalf("append:\n%s", d)
	}
	d = Diff([]byte("a\nb\nc\n"), []byte("a\nc\n"))
	if !strings.Contains(d, "-b\n") || strings.Contains(d, "+") && strings.Contains(d, "+a") {
		t.Fatalf("remove:\n%s", d)
	}
	d = Diff(nil, []byte("x\ny\n"))
	if !strings.Contains(d, "@@ -0,0 +1,2 @@\n+x\n+y\n") {
		t.Fatalf("from empty:\n%s", d)
	}
}

// TestDiffEveryLineAccounted: applying the diff's -/+ lines to a gives b,
// for a set of edits, so no change is ever hidden from the approver.
func TestDiffEveryLineAccounted(t *testing.T) {
	base := strings.Split("a b c d e f g h i j k l m n o p", " ")
	edits := []func([]string) []string{
		func(s []string) []string { return append([]string{"new"}, s...) },
		func(s []string) []string { return s[3:] },
		func(s []string) []string { s = append([]string(nil), s...); s[8] = "changed"; return s },
		func(s []string) []string { return append(append([]string(nil), s[:5]...), s[10:]...) },
		func(s []string) []string { return []string{"entirely", "different"} },
	}
	for i, edit := range edits {
		x := base
		y := edit(base)
		ops := diffOps(x, y)
		var gotA, gotB []string
		for _, op := range ops {
			if op.kind != '+' {
				gotA = append(gotA, op.text)
			}
			if op.kind != '-' {
				gotB = append(gotB, op.text)
			}
		}
		if strings.Join(gotA, " ") != strings.Join(x, " ") || strings.Join(gotB, " ") != strings.Join(y, " ") {
			t.Errorf("edit %d: ops don't reproduce the inputs", i)
		}
	}
}
