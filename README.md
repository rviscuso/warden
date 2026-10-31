# Warden

**The agent gets the repo. Warden guards the rest.**

Warden is a control plane for sandboxed agentic development. One CLI puts a coding agent
such as Claude Code in a hardened container where it can change the repository and nothing
else, reach only pre-approved domains, and expose no port Warden hasn't declared.

No more hand-maintained compose files, firewall scripts and Docker flags: declare the
sandbox, and Warden builds it, proves it holds, and keeps it that way. Warden itself is
deterministic: no AI runs in the control plane, and every change to the sandbox needs
human approval.

Written in Go with no third-party dependencies.

**Status: early development.** See [DESIGN.md](DESIGN.md) for the design and threat model.

| Phase | Scope | Status |
|---|---|---|
| 1 | `init` / `check` (prerequisites + canary isolation checks), egress proxy with domain allowlist, controller `up` / `down` / `status` / `logs` | In progress |
| 2 | Direct push with a machine-account token | Not started |
| 3 | Services: MCP servers and apps, declared ports, per-service egress | Not started |
| 4 | Approved actions that need secrets, extra egress or another image | Not started |
| 5 | `publish` via bundles into a clean clone | Not started |

Nothing is verified against a real Docker daemon yet. This table will say when it is.
