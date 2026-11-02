package canary

import (
	"errors"
	"strings"

	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/hardening"
)

// Names. They differ from up's, so the canary can run while Warden is up.
const (
	ProjectName = "warden-canary"
	ProxyName   = "warden-canary-proxy"
	CanaryName  = "warden-canary"
	SandboxNet  = "warden-canary-sandbox"
	EgressNet   = "warden-canary-egress"

	// DenyHost is never on an allowlist: .invalid is reserved (RFC 2606).
	DenyHost = "warden-canary.invalid"

	// RouteControl is the address the canary must not reach directly.
	// 1.1.1.1 is a well-known public resolver address: stable and globally
	// routable, so if the host reaches it and the canary doesn't, the
	// sandbox has no route out. Nothing is sent to it.
	RouteControl = "1.1.1.1:443"

	BinaryTarget = "/warden"
	MountTarget  = "/canary"
	ProxyPort    = "3128"
)

// ProjectParams are the canary's inputs.
type ProjectParams struct {
	UID, GID     int
	RuntimeImage string
	Binary       string // <state>/bin/warden-<sha256>
	MountDir     string // <state>/canary/<random>/mnt
	Allow        []string
	Resources    hardening.Resources // controller.resources
	Host         hardening.Host
}

// ProbeHost is the host the canary uses for proxy-allow and no-dns: the
// first exact allowlist entry, or else the domain of the first leading-dot
// entry.
func ProbeHost(allow []string) (string, error) {
	for _, a := range allow {
		if !strings.HasPrefix(a, ".") {
			return a, nil
		}
	}
	if len(allow) > 0 {
		return strings.TrimPrefix(allow[0], "."), nil
	}
	return "", errors.New("the allowlist is empty")
}

// Project builds the canary's compose project: the proxy exactly as up
// runs it, and the canary on the sandbox network only.
func Project(p ProjectParams) (compose.File, error) {
	host, err := ProbeHost(p.Allow)
	if err != nil {
		return compose.File{}, err
	}
	proxyH, err := hardening.Settings(p.UID, p.GID, hardening.ProxyResources, p.Host)
	if err != nil {
		return compose.File{}, err
	}
	canaryH, err := hardening.Settings(p.UID, p.GID, p.Resources, p.Host)
	if err != nil {
		return compose.File{}, err
	}
	bin := compose.BindMount(p.Binary, BinaryTarget, true)
	proxyCmd := []string{"proxy", "--listen", ":" + ProxyPort}
	for _, a := range p.Allow {
		proxyCmd = append(proxyCmd, "--allow", a)
	}
	proxyCmd = append(proxyCmd, "--ports", "443")
	return compose.File{
		Name: ProjectName,
		Services: map[string]compose.Service{
			"proxy": {
				Fields:        proxyH,
				ContainerName: ProxyName,
				Image:         p.RuntimeImage,
				Entrypoint:    []string{BinaryTarget},
				Command:       proxyCmd,
				Environment:   map[string]string{"WARDEN_ROLE": "proxy"},
				Networks:      []string{"sandbox", "egress"},
				Volumes:       []compose.Bind{bin},
			},
			"canary": {
				Fields:        canaryH,
				ContainerName: CanaryName,
				Image:         p.RuntimeImage,
				Entrypoint:    []string{BinaryTarget},
				Command: []string{"probe",
					"--proxy", ProxyName + ":" + ProxyPort,
					"--allow-host", host,
					"--deny-host", DenyHost,
					"--dns-host", host,
					"--route", RouteControl,
					"--dir", MountTarget,
				},
				Environment: map[string]string{"WARDEN_ROLE": "canary"},
				Networks:    []string{"sandbox"},
				Volumes:     []compose.Bind{bin, compose.BindMount(p.MountDir, MountTarget, false)},
				DependsOn:   []string{"proxy"},
			},
		},
		Networks: map[string]compose.Network{
			"sandbox": {Name: SandboxNet, Internal: true},
			"egress":  {Name: EgressNet},
		},
	}, nil
}
