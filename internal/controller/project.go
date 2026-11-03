// Package controller runs Warden's sandbox: it generates the compose
// project (the egress proxy and the controller), and implements up, down,
// status and logs, post-start verification and the Remote Control URL. See
// docs/phase-1.md, "Controller".
package controller

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/rviscuso/warden/internal/compose"
	"github.com/rviscuso/warden/internal/hardening"
)

// Names of up's project. The canary uses others, so it can run while
// Warden is up.
const (
	ProjectName    = "warden"
	ProxyName      = "warden-proxy"
	ControllerName = "warden-controller"
	SandboxNet     = "warden-sandbox"
	EgressNet      = "warden-egress"

	ProxyPort       = "3128"
	BinaryTarget    = "/warden"
	WorkspaceTarget = "/workspace"
	HomeTarget      = "/home/agent"
)

// ProxyParams are the proxy service's inputs.
type ProxyParams struct {
	UID, GID      int
	ContainerName string
	RuntimeImage  string
	Binary        string // <state>/bin/warden-<sha256>
	Allow         []string
	Host          hardening.Host // the host kernel: see hardening.HostMPTCP
}

// ProxyService is the egress proxy as every Warden project runs it: up's
// and the canary's. Its service key is "proxy" and it joins the networks
// keyed "sandbox" and "egress".
func ProxyService(p ProxyParams) (compose.Service, error) {
	if len(p.Allow) == 0 {
		return compose.Service{}, errors.New("controller: the allowlist is empty")
	}
	h, err := hardening.Settings(p.UID, p.GID, hardening.ProxyResources, p.Host)
	if err != nil {
		return compose.Service{}, err
	}
	cmd := []string{"proxy", "--listen", ":" + ProxyPort}
	for _, a := range p.Allow {
		cmd = append(cmd, "--allow", a)
	}
	cmd = append(cmd, "--ports", "443")
	return compose.Service{
		Fields:        h,
		ContainerName: p.ContainerName,
		Image:         p.RuntimeImage,
		Entrypoint:    []string{BinaryTarget},
		Command:       cmd,
		Environment:   map[string]string{"WARDEN_ROLE": "proxy"},
		Networks:      []string{"sandbox", "egress"},
		Volumes:       []compose.Bind{compose.BindMount(p.Binary, BinaryTarget, true)},
	}, nil
}

// Environment is the controller's environment: fixed, not configurable.
// HTTPS_PROXY and https_proxy are both set because some tools read only one.
func Environment() map[string]string {
	proxy := "http://" + ProxyName + ":" + ProxyPort
	return map[string]string{
		"HTTPS_PROXY":                 proxy,
		"https_proxy":                 proxy,
		"CLAUDE_CONFIG_DIR":           HomeTarget + "/.claude",
		"DISABLE_AUTOUPDATER":         "1",
		"ENABLE_CLAUDEAI_MCP_SERVERS": "false",
		"DISABLE_TELEMETRY":           "1",
		"DISABLE_ERROR_REPORTING":     "1",
	}
}

// Params are up's inputs. Workspace must be the path mount validation
// resolved; AgentHome the directory up created or checked.
type Params struct {
	UID, GID          int
	RuntimeImage      string
	Binary            string
	Allow             []string
	Image             string // controller.image
	Workspace         string
	AgentHome         string
	RemoteControlName string
	Resources         hardening.Resources
	Host              hardening.Host
}

// Project builds up's compose project.
func Project(p Params) (compose.File, error) {
	for name, path := range map[string]string{"workspace": p.Workspace, "agent home": p.AgentHome, "binary": p.Binary} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return compose.File{}, fmt.Errorf("controller: %s %q must be an absolute, clean path", name, path)
		}
	}
	if p.RemoteControlName == "" {
		return compose.File{}, errors.New("controller: remote_control_name is empty")
	}
	proxy, err := ProxyService(ProxyParams{
		UID: p.UID, GID: p.GID, ContainerName: ProxyName,
		RuntimeImage: p.RuntimeImage, Binary: p.Binary, Allow: p.Allow, Host: p.Host,
	})
	if err != nil {
		return compose.File{}, err
	}
	h, err := hardening.Settings(p.UID, p.GID, p.Resources, p.Host)
	if err != nil {
		return compose.File{}, err
	}
	return compose.File{
		Name: ProjectName,
		Services: map[string]compose.Service{
			"proxy": proxy,
			"controller": {
				Fields:        h,
				ContainerName: ControllerName,
				Image:         p.Image,
				Entrypoint:    []string{"claude"},
				Command:       []string{"--remote-control", p.RemoteControlName},
				Environment:   Environment(),
				Networks:      []string{"sandbox"},
				Volumes: []compose.Bind{
					compose.BindMount(p.Workspace, WorkspaceTarget, false),
					compose.BindMount(p.AgentHome, HomeTarget, false),
				},
				DependsOn: []string{"proxy"},
				TTY:       true,
				StdinOpen: true,
			},
		},
		Networks: map[string]compose.Network{
			"sandbox": {Name: SandboxNet, Internal: true},
			"egress":  {Name: EgressNet},
		},
	}, nil
}
