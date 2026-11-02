package controller

import (
	"fmt"
	"strings"
)

// diffContext is the number of unchanged lines shown around each change.
const diffContext = 3

// maxDiffCells caps the LCS table (lines(a) * lines(b)). A compose file is
// a few hundred lines; anything near this is not one, and gets a whole-file
// replacement instead of a slow diff.
const maxDiffCells = 4 << 20

// Diff is a unified-style line diff from a to b, headed "--- applied" and
// "+++ new", with @@ hunks and diffContext lines of context. Equal inputs
// give "". It is for people reading an approval prompt, not for patch.
func Diff(a, b []byte) string {
	if string(a) == string(b) {
		return ""
	}
	x, y := lines(string(a)), lines(string(b))
	ops := diffOps(x, y)

	var out strings.Builder
	out.WriteString("--- applied\n+++ new\n")
	// Group ops into hunks: changes with up to 2*diffContext equal lines
	// between them share a hunk.
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := max(i-diffContext, 0)
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*diffContext {
				end = min(end+diffContext, len(ops))
				break
			}
			end = run
		}
		h := ops[start:end]
		aStart, bStart, aLen, bLen := h[0].ai, h[0].bi, 0, 0
		for _, op := range h {
			if op.kind != '+' {
				aLen++
			}
			if op.kind != '-' {
				bLen++
			}
		}
		fmt.Fprintf(&out, "@@ -%s +%s @@\n", hunkRange(aStart, aLen), hunkRange(bStart, bLen))
		for _, op := range h {
			out.WriteByte(op.kind)
			out.WriteString(op.text)
			out.WriteByte('\n')
		}
		i = end
	}
	return out.String()
}

type diffOp struct {
	kind   byte // ' ', '-' or '+'
	text   string
	ai, bi int // 0-based line positions in a and b where this op starts
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func hunkRange(start, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", start)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}

// diffOps is a longest-common-subsequence diff: every line of x is kept
// or removed, every line of y kept or added.
func diffOps(x, y []string) []diffOp {
	if (len(x)+1)*(len(y)+1) > maxDiffCells {
		var ops []diffOp
		for i, l := range x {
			ops = append(ops, diffOp{'-', l, i, 0})
		}
		for j, l := range y {
			ops = append(ops, diffOp{'+', l, len(x), j})
		}
		return ops
	}
	// lcs[i][j] is the LCS length of x[i:] and y[j:].
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < len(x) || j < len(y) {
		switch {
		case i < len(x) && j < len(y) && x[i] == y[j]:
			ops = append(ops, diffOp{' ', x[i], i, j})
			i++
			j++
		case i < len(x) && (j == len(y) || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, diffOp{'-', x[i], i, j}) // removals before additions
			i++
		default:
			ops = append(ops, diffOp{'+', y[j], i, j})
			j++
		}
	}
	return ops
}
