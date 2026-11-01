package config

import (
	"strings"
	"testing"
)

// replaceOnce swaps exactly one occurrence of old in the valid config.
func replaceOnce(t *testing.T, old, new string) []byte {
	t.Helper()
	if strings.Count(validJS, old) != 1 {
		t.Fatalf("%q must occur exactly once in validJS", old)
	}
	return []byte(strings.Replace(validJS, old, new, 1))
}

func TestCaseVariantKeysRejected(t *testing.T) {
	cases := map[string][2]string{
		"top level":     {`"version": 1`, `"Version": 1`},
		"nested":        {`"socket": "/var/run/docker.sock"`, `"Socket": "/var/run/docker.sock"`},
		"in controller": {`"remote_control_name"`, `"Remote_Control_Name"`},
		"deep":          {`"memory_mb": 1536`, `"MEMORY_MB": 1536`},
		"egress":        {`"allow"`, `"ALLOW"`},
		"unicode fold":  {`"socket": "/var/run/docker.sock"`, `"ſocket": "/var/run/docker.sock"`}, // ſ folds to s
		"kelvin sign":   {`"workspace"`, `"wor\u212aspace"`},                                      // U+212A KELVIN SIGN folds to k
		"escaped upper": {`"pids"`, `"\u0050ids"`},                                                // \u0050 is P
	}
	for name, c := range cases {
		_, err := Parse(replaceOnce(t, c[0], c[1]))
		if err == nil || !strings.Contains(err.Error(), "only by case") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestCaseVariantErrorNamesTheField(t *testing.T) {
	_, err := Parse(replaceOnce(t, `"socket": "/var/run/docker.sock"`, `"Socket": "/var/run/docker.sock"`))
	want := `config: docker.Socket: key differs from "socket" only by case (keys are case-sensitive)`
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}

func TestDuplicateKeysRejected(t *testing.T) {
	cases := map[string][2]string{
		"top level":         {`"version": 1,`, `"version": 1, "version": 1,`},
		"nested":            {`"socket": "/var/run/docker.sock"`, `"socket": "/var/run/docker.sock", "socket": "/run/docker.sock"`},
		"deep":              {`"pids": 512`, `"pids": 512, "pids": 64`},
		"workspace":         {`"workspace": "/srv/work/repo",`, `"workspace": "/srv/work/repo", "workspace": "/",`},
		"escaped":           {`"pids": 512`, `"pids": 512, "p\u0069ds": 64`}, // \u0069 is i
		"in unknown object": {`"version": 1,`, `"version": 1, "extra": {"a": 1, "a": 2},`},
		"in array element":  {`"version": 1,`, `"version": 1, "extra": [{"a": 1, "a": 2}],`},
	}
	for name, c := range cases {
		_, err := Parse(replaceOnce(t, c[0], c[1]))
		if err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestDuplicateErrorNamesTheObject(t *testing.T) {
	_, err := Parse(replaceOnce(t, `"pids": 512`, `"pids": 512, "pids": 64`))
	want := `config: controller.resources: duplicate key "pids"`
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	_, err = Parse(replaceOnce(t, `"version": 1,`, `"version": 1, "version": 1,`))
	if want := `config: top level: duplicate key "version"`; err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}

func TestSameKeyInDifferentObjectsIsFine(t *testing.T) {
	// "image" appears once at controller level; a same-named key in a
	// sibling object is not a duplicate. Unknown keys still fail later.
	c, err := Parse([]byte(validJS))
	if err != nil || c == nil {
		t.Fatal(err)
	}
	_, err = Parse(replaceOnce(t, `"version": 1,`, `"version": 1, "x": {"version": 1},`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "x"`) {
		t.Fatalf("got %v", err)
	}
}

func TestAllowListValuesAreNotKeys(t *testing.T) {
	// Duplicate *values* in arrays are the allowlist rule's job, not the
	// key pre-pass.
	_, err := Parse(replaceOnce(t, `["api.anthropic.com", "platform.claude.com"]`, `["api.anthropic.com", "api.anthropic.com"]`))
	if err == nil || !strings.Contains(err.Error(), `egress.allow[1]: duplicate entry`) {
		t.Fatalf("got %v", err)
	}
}
