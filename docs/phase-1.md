# Phase 1: sandbox, egress proxy, controller

Read `DESIGN.md` first. This file is the spec for phase 1. If anything here is ambiguous or
looks wrong, stop and ask; don't guess.

## Deliverable

A Go module `github.com/rviscuso/warden`, `go 1.27`, with **no `require` lines** in `go.mod`.
One static binary, `warden`, built with `CGO_ENABLED=0`. It runs as the invoking user, never as root.

```
warden version
warden init     [--json]            checks + canary; on success records state
warden check    [--json]            same checks and canary, read-only: re-prove the sandbox holds
warden up                           start the proxy and the controller (asks y/N)
warden down                         stop and remove them (agent home and workspace are kept)
warden status   [--json]            daemon pin, container states, Remote Control URL
warden logs     proxy|controller [-n N]
warden proxy    [flags]             the egress proxy itself; runs inside the proxy container
```

`warden proxy` is internal: it isn't listed in the main help, and it refuses to run unless
`WARDEN_ROLE=proxy` is set (Warden sets it in the proxy container).

Exit codes: 0 success, 1 a check failed or the operation failed, 2 usage error.

- `--help` (or `-h`) on any command prints usage to stdout and exits 0. A usage error prints the
  error and usage to stderr and exits 2.
- `warden proxy --help` works without `WARDEN_ROLE`; only running the proxy requires it.
- A command whose milestone hasn't landed yet prints `not implemented` to stderr and exits 1.
- `warden version` reads Go's embedded build info (`runtime/debug.ReadBuildInfo`): the module
  version, `vcs.revision` and `vcs.modified`. No `-ldflags`.

## Directories

Resolved with the XDG base-directory rules (`$XDG_CONFIG_HOME`, `$XDG_STATE_HOME`,
`$XDG_DATA_HOME`, falling back to the defaults below). Created with mode 0700.

| Purpose | Default | Agent can write? |
|---|---|---|
| Config | `~/.config/warden/config.json` | No, never mountable |
| State | `~/.local/state/warden/` (`state.json`, `compose/`, `docker-config/`) | No, never mountable |
| Agent homes | `~/.local/share/warden/agents/<name>/` | Yes: mounted as the agent's `$HOME` |

- A relative `XDG_*` value is ignored (per the XDG spec) and the default is used.
- `internal/paths` only works out locations; it creates nothing.
- Commands that need a directory create it (`init`; the Docker runner for `docker-config/`).
  Other commands fail with "run warden init" if it is missing.
- An existing directory with permissions looser than 0700, or not owned by the invoking user, is an
  error with the exact fix (e.g. `chmod 700 <dir>`). Warden never changes permissions silently.

## Package layout

```
cmd/warden/            main: calls cli.Run(os.Args, stdin, stdout, stderr) and exits with its code
internal/cli/          subcommand dispatch, one flag.FlagSet per subcommand, help text
internal/paths/        XDG resolution for the directories above
internal/config/       load + validate config.json (strict JSON)
internal/mounts/       mount validation (security-critical, see below)
internal/state/        state.json: daemon pin, last applied compose, last Remote Control URL
internal/docker/       Runner interface + exec implementation with a sanitized environment
internal/hardening/    THE single source of container hardening, used by every container
internal/checks/       host, daemon and canary checks; a Result per check
internal/proxy/        the egress proxy: allowlist, CONNECT handling, connection log
internal/controller/   compose generation, up/down/status/logs, post-start verification, RC URL
images/controller/     reference controller image (Dockerfile only)
```

Everything that touches the outside world sits behind an interface so tests need no Docker,
no special privileges and no network:
- `docker.Runner`: `Run(ctx, args []string, stdin io.Reader) (stdout, stderr []byte, exitCode int, err error)`.
- A filesystem root for host checks (tests point it at a temp directory with fixture files).
- The current UID, GID and home directory, a clock, and stdin for the y/N prompt.
- For the proxy: a resolver and a dialer, so tests run against local listeners.

## Config

```json
{
  "version": 1,
  "docker": { "socket": "/var/run/docker.sock" },
  "runtime_image": "busybox@sha256:…",
  "egress": {
    "allow": ["api.anthropic.com", "platform.claude.com"]
  },
  "controller": {
    "image": "sha256:…",
    "workspace": "/home/alice/code/myrepo",
    "remote_control_name": "warden",
    "resources": { "memory_mb": 1536, "cpus": 1.5, "pids": 512 }
  }
}
```

`runtime_image` is the one stock image Warden's own containers (canary and proxy) run from,
with the `warden` binary mounted read-only. It needs a shell and `nc` for the canary probe;
busybox fits.

There is no UID field: the agent always runs as the invoking user's UID and GID, taken at runtime.
There is no field for privileged mode, capabilities, host namespaces, devices, extra mounts, ports
or the Docker socket. That is the point.

Validation (each rule has a failing test):
- unknown fields anywhere → error;
- `version` must be 1;
- `docker.socket` is optional and defaults to `/var/run/docker.sock`; if set, it must be an absolute path;
- images must be `name@sha256:<64 hex>` or `sha256:<64 hex>`; tags are rejected;
- `egress.allow`: non-empty; each entry a lowercase hostname, optionally with a leading dot for
  subdomains; no schemes, paths, ports, wildcards or IP addresses. Precisely:
  - labels are LDH only: `a-z`, `0-9` and `-`, with no hyphen at the start or end of a label;
  - at least two labels (`localhost` is rejected); a leading-dot entry needs at least two labels
    after the dot (`.com` is rejected);
  - no trailing dot;
  - punycode (`xn--…`) labels are allowed;
  - at most 253 characters overall and 63 per label;
  - duplicate entries are an error;
- `remote_control_name` must match `^[a-zA-Z0-9._-]{1,64}$`;
- resources: `memory_mb` 256 to 65536; `cpus` 0.25 to 64 (fractions allowed); `pids` 64 to 32768;
- `workspace` must be an absolute path.

`internal/config` validates format only. The workspace is checked by `internal/mounts`; the command
layer runs both (and `up` re-runs mount validation anyway).

## Mount validation (`internal/mounts`, security-critical)

The agent runs with the user's UID, so file permissions don't protect the user's files: anything
mounted is writable to it. Only what is mounted is reachable, so this validation is what enforces
"repo only" (see `DESIGN.md`, section 6). Every path is made absolute and resolved with
`filepath.EvalSymlinks` before any comparison. A workspace is refused if it:
- doesn't exist, isn't a directory, or isn't owned by the invoking user;
- is `/`, the user's home directory, or an ancestor of the home directory;
- is, is inside, or contains Warden's config, state or agent-home directories;
- is, is inside, or contains any of: `~/.ssh`, `~/.config`, `~/.local`, `~/.aws`, `~/.azure`, `~/.docker`, `~/.gnupg`, `~/.kube`, `~/.netrc`, `~/.bashrc`, `~/.profile`, `~/.zshrc`;
- is, is inside, or contains a system directory (`/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/var`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`, `/root`, `/tmp`, `/snap`) or the Docker socket.

Each forbidden path (Warden's directories, the home directory, the dotfile list, the system
directories, the Docker socket) is compared in every one of these forms:
- as written (cleaned);
- when it exists, as resolved by `filepath.EvalSymlinks` (so `~/.config -> /data/dotfiles/config`
  or `/var/run -> /run` can't be bypassed);
- partially resolved: walked one component at a time, following every symlink (including a
  dangling one) and keeping missing components as written. This is where the path would land if it
  were created now: a dangling `~/.ssh -> /data/ssh` yields `/data/ssh`, so a workspace `/data` is
  refused. For an existing path it equals the `EvalSymlinks` form.

A forbidden path that doesn't exist is not a failure. Any other resolution error (a symlink loop,
permission denied) refuses the workspace. `/opt`, `/srv`, `/mnt` and `/media` are allowed; the
ownership rule covers them.

The same checks run on every `up`, not only at config load, because the filesystem can change.
Tests cover each rule, symlinks pointing into a forbidden path, `..` segments, and trailing slashes.

## Docker runner

- Finds the `docker` binary at a fixed path list (`/usr/bin/docker`, `/usr/local/bin/docker`), not `$PATH`.
- Runs it with a clean environment: `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `HOME` (the user's),
  `DOCKER_HOST=unix://<socket from config>`, `DOCKER_CONFIG=<state>/docker-config` (created empty, 0700).
  Nothing else is inherited.
- The runner creates `<state>/docker-config` with mode 0700 if it is missing. If it exists with
  looser permissions or another owner, the runner fails with the exact fix; it never changes
  permissions silently.
- argv only. Never `sh -c`.
- Every call has a timeout: 30 seconds by default; callers override it (`docker compose up`/`down`: 5 minutes).

## Hardening (`internal/hardening`)

One function produces every container's security settings, with no exceptions in phase 1:
`user: <uid>:<gid>`, `cap_drop: [ALL]`, `no-new-privileges`, default seccomp, `read_only: true`
with a `tmpfs` for `/tmp`, memory, CPU and PID limits, and `init: true`.

A unit test asserts that no code path can produce `privileged`, any `cap_add`, `user` 0 or empty,
`pid`/`ipc`/`network: host`, `devices`, or a mount of the Docker socket.

Note: `read_only` may break an image that writes outside its mounts. If the controller image can't
run read-only, stop and ask; don't silently turn it off.

## Networks

Created by Warden, project-scoped, removed by `down`:
- `warden-sandbox`: `internal: true`. The controller joins only this one.
- `warden-egress`: a normal bridge network. Only the proxy joins it.

## Egress proxy (`internal/proxy`, `warden proxy`)

A working prototype of this design was tested on a real host (see "Prototype results" below).

- Accepts only `CONNECT`. Anything else gets 405.
- Destination port must be in the allowed set (default: 443).
- The target must be a hostname on the allowlist (exact match, or a leading-dot entry matching the
  domain and its subdomains, case-insensitive, trailing dot ignored). IP literals are refused.
- Resolves the name itself and dials only public unicast addresses: refuses private, loopback,
  link-local, multicast, unspecified and carrier-grade NAT (`100.64.0.0/10`) ranges.
- Splices bytes both ways; half-closes correctly; includes any bytes already buffered by the HTTP server.
- **No idle timeout on tunnels.** Remote Control holds connections open for over an hour.
- Header read timeout, a dial timeout, and a cap on concurrent tunnels.
- **Logs one JSON line when a tunnel opens and one when it closes** (time, event, client, host, port,
  decision, reason, bytes up and down, duration), to stdout. A deny is one line with its reason.
- Takes its allowlist and ports from flags that Warden passes; it reads no config file.

Proxy container: `runtime_image`, the `warden` binary bind-mounted read-only, command
`warden proxy --listen :3128 --allow … --ports 443`, `WARDEN_ROLE=proxy`, hardening from
`internal/hardening`, on both networks, container name `warden-proxy`.

Tests: allowlist matching (exact, subdomain, case, trailing dot, near-misses like
`evilapi.anthropic.com` and `api.anthropic.com.evil.org`), every deny path, private-address
refusal, a full tunnel against a local listener, and log lines for open and close.

## Checks

Each check returns `{id, title, status: pass|warn|fail, detail, fix}`. `fix` is an exact command
or instruction for the user. Output is one table (or JSON with `--json`). Any `fail` → exit 1.

**Host**

| ID | Check | Fail or warn |
|---|---|---|
| host.not-root | Effective UID is not 0 | fail: "run Warden as your own user, not root or sudo" |
| host.os | Linux, amd64 or arm64 | fail |
| host.cgroup2 | `/sys/fs/cgroup/cgroup.controllers` exists | fail |
| host.docker-cli | `docker` found at a fixed path | fail |
| host.compose | `docker compose version` works | fail |
| host.docker-access | The configured socket is accessible to the user | fail, with the fix (add the user to `docker`, log in again); always also prints: "Docker socket access is root-equivalent on this host" |

**Daemon** (parsed from `docker info --format '{{json .}}'` and `docker version --format '{{json .}}'`)

| ID | Check | Fail or warn |
|---|---|---|
| daemon.reachable | The configured socket answers | fail |
| daemon.mode | `SecurityOptions` has no `name=rootless` and no `name=userns` | fail: "not supported in v1" |
| daemon.cgroup | `CgroupVersion` is `2` | fail |
| daemon.seccomp | `SecurityOptions` has `name=seccomp` | fail |
| daemon.apparmor | `SecurityOptions` has `name=apparmor` | warn: weaker isolation |
| daemon.version | Server version recorded; warn if older than the versions listed as tested | warn |
| daemon.pin | On `check`/`up`/`status`: daemon `ID` equals the pinned ID | fail: "daemon changed; re-run init" |

Parsing is tested against recorded `docker info` JSON fixtures: rootful, rootless, userns-remap,
cgroup v1, no AppArmor, unreachable.

**Canary** (`init` and `check` only)

- `runtime_image` must be pinned by digest, or the check fails.
- Warden creates temporary `warden-canary-sandbox` (internal) and `warden-canary-egress` networks,
  starts a temporary proxy exactly as `up` would (allowlist from config), and starts the canary as the
  user's UID:GID with `hardening.Settings(...)` on the sandbox network, with a temporary directory from
  Warden's state directory bind-mounted. One probe script prints `key=value` lines; Warden parses them.
  Everything is always removed, even on failure.

| ID | Assertion |
|---|---|
| canary.caps | `CapEff` and `CapBnd` are `0000000000000000` |
| canary.nnp | `NoNewPrivs` is `1` |
| canary.seccomp | `Seccomp` is `2` |
| canary.uid | `Uid` and `Gid` equal the user's |
| canary.memory | `/sys/fs/cgroup/memory.max` equals the requested bytes |
| canary.pids | `/sys/fs/cgroup/pids.max` equals the requested limit |
| canary.cpu | `/sys/fs/cgroup/cpu.max` matches the requested quota |
| canary.apparmor | `/proc/self/attr/current` is `docker-default (enforce)` (warn if the daemon has no AppArmor) |
| canary.rootfs | Writing to `/` fails |
| canary.no-route | A TCP connection to a public IP fails within a short timeout |
| canary.no-dns | An outside hostname does not resolve |
| canary.no-host | Warden opens a temporary TCP listener on the host on all addresses; a connection from the canary to the sandbox network's gateway on that port fails. Warden owns both ends, so the result doesn't depend on what else runs on the host |
| canary.proxy-allow | `CONNECT` to the first allowlisted host through the proxy returns `200` |
| canary.proxy-deny | `CONNECT` to a host not on the allowlist is refused |
| canary.owner | A file the canary writes to the bind mount is owned by the user's UID and GID on the host |

## Reference controller image (`images/controller/Dockerfile`)

Built by the user for now (`docker build`), then referenced in config by image ID. It follows the
image contract in `DESIGN.md`:
- `debian:bookworm-slim` base, pinned by digest; `ca-certificates`, `git`, `ripgrep`, `less`, `procps`;
- Claude Code installed **outside `$HOME`**;
- no `USER root` entrypoint, no firewall, no `iptables`: the image runs as whatever UID Warden passes;
- `HOME=/home/agent`, `WORKDIR /workspace`.

Open question to verify, not assume: whether Claude Code's native installer supports installing
outside `$HOME`. If it doesn't, stop and present the alternatives.

## Controller

`up`:
1. Load config, check the daemon pin, re-run mount validation.
2. Create the agent home `~/.local/share/warden/agents/controller/` (0700) if missing.
3. Generate `<state>/compose/warden.json`: project `warden` with
   - the two networks;
   - the proxy service (see above);
   - the controller service, container name `warden-controller`: the workspace bind-mounted at
     `/workspace` and the agent home at `/home/agent`; `tty: true`, `stdin_open: true`; network
     `warden-sandbox` only; command `claude --remote-control <remote_control_name>`; hardening from
     `internal/hardening`; no ports; no restart policy; `depends_on` the proxy.
   - Controller environment is fixed, not configurable:
     `HTTPS_PROXY` and `https_proxy` (both set, since some tools read only one) `=http://warden-proxy:3128`, `CLAUDE_CONFIG_DIR=/home/agent/.claude`,
     `DISABLE_AUTOUPDATER=1`, `ENABLE_CLAUDEAI_MCP_SERVERS=false`, `DISABLE_TELEMETRY=1`,
     `DISABLE_ERROR_REPORTING=1`.
4. Show the generated file and a diff against the last applied one. Ask `Apply? [y/N]`. Anything but `y` stops.
5. `docker compose -p warden -f <file> up -d`.
6. **Post-start verification** for the controller and the proxy: read each container's main PID from
   `docker inspect`, find the main process (the child of the container's init), and read
   `/proc/<pid>/status` on the host. `Uid` and `Gid` must equal the user's, `CapEff` and `CapBnd` must
   be zero, and `NoNewPrivs` must be 1. If not, stop everything and fail.
7. Read the Remote Control URL from `docker logs warden-controller`, matching `https://claude.ai/code/\S+`,
   with a timeout, inside **one function** (there is no documented stdout API for it yet). Save it in
   state and print it. If it isn't found, print the last log lines and: "first run? log in with
   `docker attach warden-controller`, detach with Ctrl-P Ctrl-Q."

`down`: `docker compose -p warden down` (never `-v`). `status`: daemon pin, container states, image,
start time, last URL. `logs proxy|controller`: the last N lines of that container's log.

## Prototype results

A standalone prototype of the proxy was run on a real rootful Docker host:
- With the controller only on an internal network, direct connections failed, outside names didn't
  resolve, the proxy allowed listed hosts and refused others.
- The internal network had no default route, and the host was unreachable on its gateway address,
  including on a port the host listens on for all addresses.
- Claude Code logged in, ran commands and worked over **Remote Control** with the proxy as its only exit.
- Tunnels stayed open for over an hour (Remote Control), so the proxy must not time out idle tunnels.
- Hosts actually used: `api.anthropic.com` (API and Remote Control), `platform.claude.com` (login),
  plus `downloads.claude.ai` (auto-updater: disabled above), `mcp-proxy.anthropic.com` (claude.ai
  connectors: disabled above) and `raw.githubusercontent.com` (release notes: optional).
- The prototype logged only on close, so long tunnels were invisible while open. Hence open and close logging.

## Tests

- No test needs Docker, root or the network.
- Every check, every mount rule and every proxy deny path: at least one passing and one failing test.
- Golden-file test for the generated compose JSON.
- The hardening invariants test above.
- `cli` tests run commands end to end against a fake runner and temp directories.

## Milestones (one pull request each, reviewed before the next starts)

1. Skeleton: module, `cmd/warden`, `internal/cli` with help for every command, `version`, `internal/paths`, `internal/config`, `internal/mounts`, `internal/docker`.
2. Host and daemon checks, `init` (without canary) and `check`, state file with the daemon pin.
3. `internal/proxy` and `warden proxy`.
4. `internal/hardening` and the canary (uses the proxy).
5. Reference controller image in `images/controller/`.
6. Controller: `up` (with approval prompt, post-start verification and Remote Control URL), `down`, `status`, `logs`.

## Done means

- `gofmt -l .` prints nothing; `go vet ./...` and `go test ./...` pass; `CGO_ENABLED=0 go build ./cmd/warden` succeeds.
- `go.mod` has no `require` lines.
- `warden --help` and every `warden <cmd> --help` print usage.
- Nothing is claimed as working against a real daemon. Real runs happen on the user's host, later.
