// Package images holds the images Warden uses: the runtime image for its
// own containers, pinned by digest, and the reference controller image's
// Dockerfile, compiled into the binary so Warden never builds from a file
// on disk (DESIGN.md, sections 2 and 6). images_test.go checks the
// Dockerfile against the controller image contract.
package images

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// RuntimeImage is the one stock image Warden's own containers (canary and
// proxy) run from: busybox:stable, pinned by the multi-arch index digest
// recorded on the operator's host. Warden pulls only this image, only by
// this digest, and only on the user's "y" in the guided init.
const RuntimeImage = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

// ControllerDockerfile is images/controller/Dockerfile as it was at build
// time. A build context holds this and nothing else.
//
//go:embed controller/Dockerfile
var ControllerDockerfile []byte

// DockerfileSHA256 is the hex SHA-256 of ControllerDockerfile; the
// reference build record compares it to decide whether a build is reusable.
func DockerfileSHA256() string {
	sum := sha256.Sum256(ControllerDockerfile)
	return hex.EncodeToString(sum[:])
}

// Reference describes what the reference controller image contains, for
// the one line shown before a build.
type Reference struct {
	ClaudeVersion string   // e.g. 2.1.309
	Base          string   // the FROM reference, pinned by digest
	Packages      []string // Debian packages installed
}

var (
	baseFrom     = regexp.MustCompile(`^(\S+@sha256:[0-9a-f]{64}) AS base$`)
	claudeURL    = regexp.MustCompile(`https://downloads\.claude\.ai/claude-code-releases/(\d+\.\d+\.\d+)/linux-(?:x64|arm64)/claude`)
	aptInstall   = regexp.MustCompile(`apt-get install -y --no-install-recommends ((?:[a-z0-9][a-z0-9.+-]* )+)&&`)
	instructionW = regexp.MustCompile(`^[A-Za-z]+$`)
)

// Describe reads the Claude Code version, the base image and the packages
// from a Dockerfile shaped like the reference one. Anything missing or
// inconsistent is an error: the line shown before a build is never a guess.
func Describe(dockerfile []byte) (Reference, error) {
	ins, err := parse(string(dockerfile))
	if err != nil {
		return Reference{}, err
	}
	var ref Reference
	versions := map[string]bool{}
	for _, in := range ins {
		switch in.cmd {
		case "FROM":
			if m := baseFrom.FindStringSubmatch(in.args); m != nil {
				if ref.Base != "" {
					return Reference{}, fmt.Errorf("line %d: a second base stage", in.line)
				}
				ref.Base = m[1]
			}
		case "ADD":
			for _, m := range claudeURL.FindAllStringSubmatch(in.args, -1) {
				versions[m[1]] = true
				ref.ClaudeVersion = m[1]
			}
		case "RUN":
			if m := aptInstall.FindStringSubmatch(in.args); m != nil {
				if ref.Packages != nil {
					return Reference{}, fmt.Errorf("line %d: a second apt-get install", in.line)
				}
				ref.Packages = strings.Fields(m[1])
			}
		}
	}
	switch {
	case ref.Base == "":
		return Reference{}, fmt.Errorf("no base stage pinned by digest")
	case len(versions) != 1:
		return Reference{}, fmt.Errorf("want exactly one Claude Code version, found %d", len(versions))
	case len(ref.Packages) == 0:
		return Reference{}, fmt.Errorf("no apt-get install line")
	}
	return ref, nil
}

// String is the one line shown before a build.
func (r Reference) String() string {
	return fmt.Sprintf("Claude Code %s on %s, with %s", r.ClaudeVersion, r.Base, strings.Join(r.Packages, " "))
}

// instruction is one Dockerfile instruction, continuation lines joined.
type instruction struct {
	line int
	cmd  string // upper case: FROM, RUN, ...
	args string
}

// parse splits a Dockerfile into instructions. It handles what the
// reference image uses: comments, blank lines and backslash continuations.
// Anything it doesn't understand is an error, so a construct the contract
// can't see is never silently allowed.
func parse(src string) ([]instruction, error) {
	var out []instruction
	var cur *instruction
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if cur == nil && (line == "" || strings.HasPrefix(line, "#")) {
			continue
		}
		if cur != nil && strings.HasPrefix(line, "#") {
			continue // a comment inside a continuation
		}
		cont := strings.HasSuffix(line, "\\")
		line = strings.TrimSuffix(line, "\\")
		if cur == nil {
			cmd, args, _ := strings.Cut(line, " ")
			if !instructionW.MatchString(cmd) {
				return nil, fmt.Errorf("line %d: not an instruction: %q", i+1, raw)
			}
			cur = &instruction{line: i + 1, cmd: strings.ToUpper(cmd), args: strings.TrimSpace(args)}
		} else {
			cur.args += " " + strings.TrimSpace(line)
		}
		if !cont {
			cur.args = strings.Join(strings.Fields(cur.args), " ")
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("line %d: continuation at end of file", cur.line)
	}
	return out, nil
}
