package images

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The binary carries exactly the file the contract test checks.
func TestEmbeddedIsTheCheckedFile(t *testing.T) {
	disk, err := os.ReadFile("controller/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk, ControllerDockerfile) {
		t.Fatal("embedded Dockerfile differs from controller/Dockerfile")
	}
	for _, p := range contract(string(ControllerDockerfile)) {
		t.Error(p)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(DockerfileSHA256()) {
		t.Fatalf("DockerfileSHA256 = %q", DockerfileSHA256())
	}
}

func TestRuntimeImagePinned(t *testing.T) {
	if !regexp.MustCompile(`^busybox@sha256:[0-9a-f]{64}$`).MatchString(RuntimeImage) {
		t.Fatalf("RuntimeImage = %q, want busybox@sha256:<64 hex>", RuntimeImage)
	}
	if strings.Contains(RuntimeImage, strings.Repeat("0", 64)) {
		t.Fatal("RuntimeImage is the all-zero placeholder")
	}
}

func TestDescribe(t *testing.T) {
	ref, err := Describe(ControllerDockerfile)
	if err != nil {
		t.Fatal(err)
	}
	want := "Claude Code 2.1.309 on debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4, with ca-certificates git ripgrep less procps"
	if ref.String() != want {
		t.Fatalf("got  %s\nwant %s", ref, want)
	}
}

func TestDescribeRefuses(t *testing.T) {
	good := string(ControllerDockerfile)
	cases := map[string][2]string{
		"no digest base": {"@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS base", " AS base"},
		"two versions":   {"2.1.309/linux-arm64", "2.1.310/linux-arm64"},
		"no packages":    {"apt-get install -y --no-install-recommends", "apt-get install -y"},
		"bad syntax":     {"FROM claude-${TARGETARCH}", "-- FROM claude-${TARGETARCH}"},
	}
	for name, c := range cases {
		if !strings.Contains(good, c[0]) {
			t.Fatalf("%s: %q not in the Dockerfile", name, c[0])
		}
		if _, err := Describe([]byte(strings.Replace(good, c[0], c[1], 1))); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// scripts/e2e.sh reads the pin from this exact line of images.go.
func TestRuntimeImageLineForE2E(t *testing.T) {
	src, err := os.ReadFile("images.go")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^const RuntimeImage = "busybox@sha256:[0-9a-f]{64}"$`).Find(src)
	if string(line) != `const RuntimeImage = "`+RuntimeImage+`"` {
		t.Fatalf("e2e.sh can't find the pin; found %q", line)
	}
}
