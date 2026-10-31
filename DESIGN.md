# Warden design

**The agent gets the repo. Warden guards the rest.**

Warden is a control plane for sandboxed agentic development. One CLI puts a coding agent
such as Claude Code in a hardened container where:

- **it can change the repository, and nothing else;**
- **it can reach only pre-approved domains;**
- **no port is exposed unless Warden declares it.**

Getting those guarantees today means hand-written compose files, firewall scripts and
`docker run` flags, maintained by hand and easy to get subtly wrong. Warden ships them as a
ready-to-use control plane: declare the sandbox, and Warden builds it, proves it holds, and
keeps it that way.

Warden itself is deterministic. No AI runs in the control plane: the agent works inside the
sandbox, never on its controls. Changing the sandbox (a new domain, a port, a service) is a
proposal that a human approves before Warden applies it.

## 1. Goals

- **Repo-only writes.** The agent's only host-backed write access is its workspace (plus its own session state).
- **Allowlisted egress.** The sandbox reaches only approved domains, through a proxy that logs every connection. Everything else is denied.
- **No implicit exposure.** No ports, sockets or host paths unless Warden's spec declares them.
- **One CLI** replaces hand-maintained compose files, firewall scripts and Docker flags.
- **Safe by construction.** Unsafe container settings can't be expressed in Warden's specs.
- **Proven, not assumed.** Warden verifies isolation by observing it from inside a container, not by reading configuration.
- **Fail closed.** A check that can't run, or can't prove its result, stops Warden. It never lets things through.
- **Human-approved changes.** Any change to the sandbox is shown exactly and applied only after approval.
- **Zero third-party code.** Warden drives a Docker daemon, which is root-equivalent, so every line in the binary is trusted code. Using only Go's standard library keeps that trust limited to Warden itself and the Go toolchain, with no supply-chain risk from dependencies.
- **Runs as you.** No `sudo`. Warden refuses to run as root.

Non-goals: multiple hosts, Kubernetes, installing or reconfiguring Docker, and image builds (until there is an isolated builder).

## 2. Threat model

**Baseline.** Most developers run Claude Code directly as their own user, with access to
everything that user can reach: their home directory, SSH keys, cloud credentials, the
Docker socket and the whole internet. Warden runs the agent **with the same UID** but
inside a container that sees only the workspace, reaches only approved domains and exposes
nothing. Every Warden guarantee is an improvement over that baseline.

**What Warden protects:** the host, the user's files and credentials outside the
workspace, the Docker daemon, and other workloads on the host.

**The rule:** nothing the agent writes runs outside its sandbox unless a human has
reviewed exactly what will run.

**Escape routes Warden must keep closed:**

| Route | Why it's dangerous | Warden's answer |
|---|---|---|
| Docker socket | Socket access is root on the host. Mounting it `:ro` doesn't make the API read-only, and a "read-only" proxy still leaks (`inspect` shows env vars, `archive` copies files out) | The socket can't be expressed in a spec. Never mounted |
| Container definition | An agent that edits its own container can grant itself anything | Specs live in Warden's config directory, which can never be mounted into a container. The schema can't express privileged mode, capabilities, host namespaces, devices, arbitrary host paths or the socket |
| Network egress | An agent with open internet can download and run anything, or send the workspace anywhere | No route out: the sandbox network is internal. The only exit is Warden's proxy, which allows HTTPS to listed hostnames only, refuses IP literals and private addresses, and logs every connection. Outside names don't resolve inside the sandbox |
| Files the user later runs or loads | The agent runs with the user's UID, so any file it can write outside the workspace (`~/.bashrc`, Warden's config, SSH config) becomes code the user executes | Mount validation (section 6): the workspace can't be or contain the home directory, Warden's directories or other sensitive paths. Security-critical, with its own tests |
| Host running agent-written files | Makefiles (`GNUmakefile` and `makefile` win over `Makefile`), Compose files, Dockerfiles, scripts, Terraform `external`, wrangler build commands | Snapshot diff of execution paths against a baseline in host state, shown at approval. Only the approved file runs |
| Host git in an agent-writable repo | `.git/config` (`core.fsmonitor`, `core.hooksPath`, `core.pager`, `credential.helper`, filters, `include.path`, `url.*.insteadOf`, …), hooks, `info/attributes`, `objects/info/alternates` all run commands or redirect pushes | The host never runs git inside a repo the agent can write. Commits leave from inside the sandbox (direct push) or as bundles into a clean clone the agent never touched (`publish`). See section 8 |
| Symlinks | A path inside the workspace can point anywhere on the host | Resolve and confine every host path before use |
| Reviewing a file that then changes | A window between review and use | Copy first, then review the copy, then use the copy |
| Warden's own source | An agent that can edit Warden can disable it | Warden's source is never mounted into a container Warden manages |
| Container escape (kernel, runc) | On a rootful daemon, an escape is host root | Defence in depth: no capabilities from the first instruction, `no-new-privileges`, seccomp, AppArmor, resource limits, read-only root filesystem |

**Assumption.** Coding agents make mistakes, and they read content they didn't write
(dependencies, issues, web pages, logs) that can mislead them. Warden doesn't rely on the
agent always getting it right: the boundary holds either way.

**Accepted, out of scope:**
- The agent can always send data to its model provider; that channel is the product.
- Allowlisting is by hostname, not URL path. An allowed host is reachable in full.
- A zero-day in the kernel or Docker can defeat any container boundary. Warden reduces the odds; it does not remove them.
- Containers on a shared internal network can reach each other, so each holds only its own secrets.

## 3. Architecture

```
user ──▶ warden (CLI, runs as the user) ──argv only──▶ docker CLI ──▶ dockerd (rootful)
              │
              ├── ~/.config/warden        config + policy (never mountable)
              ├── ~/.local/state/warden   state, generated compose, logs (never mountable)
              └── ~/.local/share/warden   agent homes: session state the agent may write

   ┌──────────── sandbox network (internal: no route out, no outside DNS) ────────────┐
   │  controller (Claude Code, the user's UID, no capabilities)                       │
   │  + MCP servers, apps (phase 3)                                                   │
   │        │ HTTPS_PROXY                                                             │
   │        ▼                                                                         │
   │  egress proxy (warden proxy) ── egress network ──▶ allowlisted hosts only        │
   └──────────────────────────────────────────────────────────────────────────────────┘
```

- **Actors.** The user approves. Warden executes. The agent writes its workspace and its own session state, and runs nothing on the host.
- **Privilege.** Warden runs as the invoking user and refuses to run as root. It needs access to the Docker socket, which on a default install means being in the `docker` group. Docker documents that group as granting root-level access to the host, and `init` reminds the user of that. Warden adds no privileges of its own.
- **Driving Docker.** Warden generates compose files as JSON (valid YAML, no YAML dependency) and runs `docker compose`, passing arguments as argv (never `sh -c`). The approval prompt shows the generated file.
- **Docker environment hygiene.** Warden ignores `DOCKER_HOST` and `DOCKER_CONTEXT`. It passes the socket recorded at `init` explicitly and uses its own empty `DOCKER_CONFIG`, so no credential helper or CLI plugin from the user's Docker config runs.
- **Daemon pinning.** `init` records the daemon's socket and ID. Every later command checks the ID and refuses on a mismatch.
- **No image builds.** Warden's own containers (canary, proxy) run from one small stock image pinned by digest, with the static `warden` binary mounted read-only.

## 4. Docker modes

v1 supports Docker's default **rootful** daemon. `init` detects the mode from `docker info` (`SecurityOptions`) and refuses rootless and `userns-remap` with a clear message, because both change how container UIDs map to host files.

| Mode | An escape gives | Notes |
|---|---|---|
| Rootful (v1) | Host root | AppArmor available. Container UID = host UID |
| Rootless (not supported) | The daemon's user | No AppArmor. Limits need cgroup v2 + systemd delegation. UID offset |
| `userns-remap` (not supported) | An unprivileged mapped UID | Daemon still root. Daemon-wide. UID offset |

Docker access sits behind one interface, so supporting another mode doesn't touch callers.

## 5. Proving isolation: the canary

`init` and `check` start a short-lived **canary** container with the same hardening code
path every Warden container uses, on the same kind of network the agent gets, then assert
from inside and outside:

- effective capabilities are zero; `NoNewPrivs` is 1; seccomp is in filter mode;
- memory, PID and CPU limits appear in the container's cgroup files;
- the AppArmor profile is `docker-default` (enforce);
- the root filesystem is read-only;
- there is no direct route out, the host itself is unreachable, and outside hostnames don't resolve;
- through the proxy, an allowlisted host is reachable and any other host is refused;
- a file written to a bind mount has the expected owner on the host.

A config check reads "on"; the canary proves "enforced".

## 6. Specs, identity and mounts

**Specs**
- JSON, decoded with unknown fields rejected. A typo is an error, not a silently ignored setting.
- A `version` field on every file.
- Images are pinned by digest (`name@sha256:…`) or local image ID (`sha256:…`), never by tag.

**Agent identity**
- The agent runs with the invoking user's UID and GID, taken at runtime (`os.Getuid()`, `os.Getgid()`), never from config and never baked into an image.
- The workspace must be owned by that user. Files the agent writes are the user's files.
- The container starts as that user with every capability dropped. Nothing in it ever runs as root.
- After start, Warden reads the agent process's `/proc/<pid>/status` on the host and requires the expected `Uid`, zero `CapEff` and `CapBnd`, and `NoNewPrivs: 1`. Otherwise it stops the container.

**Mount validation (security-critical)**

The agent runs with the user's UID, so file permissions don't stop it from writing the
user's files: anything mounted into the container is fully writable to it. What keeps the
rest of the user's files out of reach is that they aren't mounted at all. Mount validation
is therefore what enforces "repo only", and it gets its own tests.

Every host path is resolved (symlinks followed) before checking, and Warden refuses a
workspace that:
- is `/`, the user's home directory, or any ancestor of the home directory;
- is, is inside, or contains Warden's config, state or share directories;
- contains the home directory's dotfiles or credential directories (`~/.ssh`, `~/.config`, `~/.aws`, `~/.docker`, `~/.gnupg`, `~/.kube`, …);
- contains the Docker socket or any system directory (`/etc`, `/usr`, `/var`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`);
- isn't owned by the invoking user.

**Controller image contract**

Warden ships a reference controller image definition in this repo (built by the user until
there is an isolated builder). Any controller image must:
- run correctly as an arbitrary non-root UID and GID, with no capabilities;
- install its tools outside `$HOME`, with self-updating turned off (rebuild the image to update);
- use `/home/agent` as `$HOME`, which Warden bind-mounts from the user's agent-home directory;
- reach the network only through `HTTPS_PROXY`, which Warden sets.

No firewall, no root entrypoint: egress control lives in the network, not in the image.

## 7. Network

- **Sandbox network** (`internal: true`): the controller, plus MCP servers and apps from phase 3. No route out, no route to the host, and no outside DNS.
- **Egress proxy**: the only container on both the sandbox network and an egress network. It is `warden proxy`, running from the stock image as the user's UID with no capabilities.
  - HTTPS only (`CONNECT`), port 443 by default.
  - Hostnames on the allowlist only; a leading dot allows subdomains. IP literals are refused.
  - Resolves names itself and refuses private, loopback and link-local addresses, so an allowed name can't be pointed at the host or a metadata service.
  - Logs every connection when it opens and when it closes, with bytes and duration.
- **Allowlist** lives in Warden's config. Changing it is a change to the sandbox, so it goes through approval.
- **Ports**: none by default. Phase 3 adds declared ports, bound to `127.0.0.1` unless stated otherwise.
- **Production** lives on a separate network with no route from the sandbox.

## 8. Getting work out

Two modes, chosen per workspace in config. In both, the host never runs git inside the workspace.

**Direct push (phase 2).** The agent pushes branches itself with a token Warden passes in.
- The token belongs to a machine account with write access to that one repository: a classic token with only `public_repo` or `repo`, never `workflow`.
- `github.com` joins the allowlist. Hostname filtering can't limit it to one repository, so the token's scope is what limits writes.
- The repository must protect its default branch (pull request required, approval by a human, no force pushes), so the agent's branches reach `main` only through review.
- `init` and `check` state what this mode gives up: a credential inside the sandbox, and branches that leave before any human sees them.

**`publish` (phase 5).** The sandbox holds no credentials and has no route to the code host.
- The agent writes an incremental git bundle. Warden fetches it into a clean clone the agent never touched, checks the tip, fast-forward and changed paths, and shows the diff, execution paths first.
- On `y`, Warden pushes with the user's own credentials.
- Works with any git host, with or without server-side branch protection.

## 9. Approved actions (phase 4)

Some work needs what the agent must not have: a deploy token, network access beyond its
allowlist, or a different toolchain image. The agent can't do it; it can only ask.

- The agent writes a request: a fixed action name plus a project and a target, never a free-form command.
- `warden approve <id>` shows the request, the diff of the files that will execute (Makefile, manifests, Dockerfile, scripts) since the last approval, and the exact container Warden will start.
- On `y`, Warden runs the action in a fresh, throwaway, hardened container with that action's own image, egress allowlist and secrets. Secrets are injected only into that container; the agent never sees them.
- Output and exit code go to a log the agent can read.

Ordinary builds and tests run inside the agent's own sandbox and don't need this.

## 10. Phases

| Phase | Scope |
|---|---|
| 1 | `init` / `check` (prerequisites + canary), egress proxy with domain allowlist and connection log, `up` / `down` / `status` / `logs` for the controller. See `docs/phase-1.md` |
| 2 | Direct push: machine-account token passed into the sandbox, `github.com` on the allowlist, `init` / `check` warnings |
| 3 | Services: MCP servers and app containers on the sandbox network, declared ports, per-service egress |
| 4 | Approved actions: `run` for work that needs secrets, extra egress or another image, with execution-path diff and run logs |
| 5 | `publish`: commits leave as bundles into a user-owned clean clone, pushed on approval |
