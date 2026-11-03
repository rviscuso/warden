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
warden probe    [flags]             the canary probe; runs inside the canary container
```

`warden proxy` is internal: it isn't listed in the main help, and it refuses to run unless
`WARDEN_ROLE=proxy` is set (Warden sets it in the proxy container). `warden probe` is the same with
`WARDEN_ROLE=canary`.

Exit codes: 0 success, 1 a check failed or the operation failed, 2 usage error.

- `--help` (or `-h`) on any command prints usage to stdout and exits 0. A usage error prints the
  error and usage to stderr and exits 2.
- `warden proxy --help` works without `WARDEN_ROLE`; only running the proxy requires it.
- A command whose milestone hasn't landed yet prints `not implemented` to stderr and exits 1.
- `warden version` reads Go's embedded build info (`runtime/debug.ReadBuildInfo`): the module
  version, `vcs.revision` and `vcs.modified`. No `-ldflags`.
- Every command except `version` and `--help` refuses to run as root (effective UID 0), at
  startup, before touching anything.

## `init` and `check`

`init`:
1. Creates the config, state and share directories (0700) if missing; an existing one that is
   looser than 0700 or not the user's fails with the exact fix.
2. If `config.json` is missing and stdin is a terminal (and there is no `--json`): the guided
   setup below (milestone 7). Otherwise, if it is missing: fails (exit 1), naming the config path
   on stderr, and prints a valid example config to stdout with a short explanation of each field on
   stderr (so stdout can be redirected straight into the file). JSON has no comments, so none are
   written. The example's `controller.image` is an all-zero placeholder; the explanation says to
   run `warden init` in a terminal to build the reference image.
3. Runs every check except `daemon.pin`. On any fail: exit 1, state unchanged.
4. Pins the daemon. If a pin exists with a different daemon ID or socket, re-pinning is a trust
   change: it prints the old and new values and asks `Re-pin to the new daemon? [y/N]` (on stderr).
   Anything but `y` keeps the old pin and exits 1. This happens only after every other check passes.

`check` runs the same checks plus `daemon.pin`, read-only: it creates nothing, and fails with
"run warden init" if a directory or the state file is missing. It writes nothing.

`state.json` (0600, written atomically) holds:
`{version: 1, warden_version, daemon: {id, socket, server_version, runc, containerd, compose}, initialized_at}`.
`warden_version` comes from build info. `daemon.pin` compares both the daemon ID and the socket.

On a terminal (stdin is a terminal and no `--json`), `init` prints its checks as one summary line
per group instead of the table (see "Guided init"). `check` always prints the full table.

## Guided init (milestone 7)

Decided with the operator before M7. Interactive only when stdin is a terminal, detected with the
`TCGETS` ioctl (a character-device test would count `/dev/null`). Without a terminal, or with
`--json`, `init` behaves exactly as above: it never prompts, pulls, builds or creates anything
beyond its directories. The guided setup runs only when `config.json` is missing; with a config,
`init` runs the checks as usual.

- **Prompts** go to stderr, one line each, reading one line from stdin. A default is shown in
  `[brackets]`; Enter accepts it. EOF at any prompt stops `init`: exit 1, nothing written.
- **Every answer is validated as entered**, with the same rules as config validation and mount
  validation. A refusal is one line: the reason, and how to write what was meant (for example
  `https://github.com/x` → "write it as github.com"; `*.example.com` → "write it as
  .example.com"; a relative path → "use an absolute path: <cwd>/<input>"). Then the prompt
  repeats.
- **The directories** (config, state, share) are created first, as today: the runner needs
  `<state>/docker-config`.

Order:

1. **Workspace** `[<current directory>]`: the default is shown only if the current directory passes
   mount validation. An existing path must pass mount validation. A path that doesn't exist is
   checked before anything is created: its parent must exist, be a directory and be the user's,
   and the would-be path (resolved parent plus the last component) must pass every forbidden-path
   rule. Then: `Create it and run git init? [y/N]`. Anything but `y` asks for the workspace again.
   On `y`:
   - `os.Mkdir` of the last component only, mode 0700; the directory must then be empty;
   - `git init -q -b main --template= <path>` on the host, the only time Warden ever runs git on
     the host, and only in that folder it has just created. `git` comes from a fixed path list
     (`/usr/bin/git`, `/usr/local/bin/git`), argv only, 30 s timeout, working directory `/`, with a
     clean environment: `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `HOME`, `GIT_CONFIG_NOSYSTEM=1`,
     `GIT_CONFIG_GLOBAL=/dev/null`. So no system or user git config and no hook template applies;
   - mount validation runs again on the created folder;
   - if any step fails, `init` stops (exit 1) with the error and the folder's path; Warden never
     removes a folder.
   Warden never runs git in an existing workspace.
2. **Allowed domains**: `api.anthropic.com` and `platform.claude.com` are always included and
   printed as such. `Add a domain (Enter to finish):` repeats; each entry is validated as an
   allowlist entry. A duplicate, including either built-in, gets "already included".
3. **Limits**: `Memory in MB [1536]`, `CPUs [1.5]`, `Process limit [512]`, each with its range.
4. **Remote Control name** `[warden]`.
5. **Runtime image**: the busybox digest pinned in code (`images.RuntimeImage`). There is no prompt
   for it and no config field. If it is local: one line, `✓ runtime image <ref>`. If not:
   `✗ runtime image not on this machine.`, the command `docker pull <ref>`, then
   `Pull it now? [y/N]`. On `y`: `docker pull <ref>` (10 minutes), then it must be local. On
   anything else, or if the pull fails: `init` continues; the checks will fail `canary.image` with
   the fix. Only that image, only by that digest.
6. **Controller image**: `Controller image ID, or "build" [<default>]`.
   - The default is the recorded reference build (below) if it is still usable, otherwise `build`.
   - An entered ID must be a valid image reference, be local and pass the contract check.
   - `build`: requires `docker buildx version` to succeed (otherwise one line with the install hint
     and the prompt repeats). Then one line naming the Claude Code version, the base image digest
     and the Debian packages, all parsed from the embedded Dockerfile; the exact build command; and
     `Build it now? [y/N]`. Anything but `y` asks for the controller image again.
   - **The build**: the Dockerfile compiled into the binary (`go:embed` of
     `images/controller/Dockerfile` in package `images`; the contract test still covers that file)
     is written to a fresh `<state>/build/<random>/context/` (directories 0700) holding nothing else.
     `docker buildx build --progress=plain --iidfile <state>/build/<random>/iid <context>`, 20 minutes,
     with Warden's empty Docker config, so buildx uses its default builder on the pinned daemon.
     The build cache is allowed. Output: the build output streams to the terminal as it runs (decided in
     review), through `internal/termsafe`: every control character except newline and tab is removed,
     including ESC and the UTF-8 C1 controls, since `RUN` steps print untrusted text. A failed build
     asks for the controller image again. The build directory is always removed.
   - **The contract check** (for a built or an entered image), from `docker image inspect`: `Os`
     `linux` and `Architecture` the host's; `Config.User` set and not root (`0`, `root`, `0:…`,
     `root:…`); no `Entrypoint` and no `Cmd`; `WorkingDir` `/workspace`; `Env` has
     `HOME=/home/agent` and `DISABLE_AUTOUPDATER=1`.
   - **The reference build record**: after a build passes the contract check, `<state>/reference-image.json`
     (0600, atomic) holds `{image_id, dockerfile_sha256, built_at}`. A later guided `init` offers it as
     the default only if the image is still local, passes the contract check, and
     `dockerfile_sha256` equals the embedded Dockerfile's. A Docker label can't serve: anyone with
     Docker access can set one. The state directory is never mounted.
7. **Review**: the full config is printed on stdout, then `Write it to <path> (mode 0600)? [y/N]`.
   Anything but `y` writes nothing and exits 1. On `y` it is written with exclusive create (if a
   config appeared meanwhile, `init` fails) in exactly the shown bytes. The docker socket is the
   default and isn't asked. A created workspace, a pulled image or a built image stays either way.
8. **Checks**: every check and the canary, then the daemon pin, as in a normal `init`.

**Summary output** (guided, and any `init` on a terminal): one line per group, in the order
`config` (`config.valid`, `workspace.valid`), `host`, `daemon`, `canary`; for example
`✓ host     7 passed` or `✗ canary   1 failed, 15 passed`. Every failing or warning check is then
printed in full with its fix. On success: `All checks passed. Pinned daemon <id> at <socket>.` and
`Next: warden up`.

**Config change:** `runtime_image` is removed from config. A config that still has it fails with
"runtime_image was removed: Warden pins it; delete the line". `version` stays 1 (phase 1 hasn't
been released).

**Tests:** unit tests drive the whole flow through the CLI with a fake terminal check, a scripted
stdin, a fake runner and a fake git, including every refusal, EOF at each prompt, `N` at each
question, and the non-terminal path unchanged. **Live test** (`TestGuidedInit`): drives `warden
init` through a pseudo-terminal (`/dev/ptmx`, standard library `syscall` only) with scripted answers:
a workspace that doesn't exist yet (created and `git init`ed), one added domain, defaults
elsewhere, `CONTROLLER_IMAGE` as the controller image, `y` at the review; the checks and canary must
pass, the config must be 0600 with those values, and the workspace must have `HEAD` on `main`.
Nothing is pulled: the pinned busybox must already be local, or the live tests fail with the
`docker pull` command. The build path is opt-in with `WARDEN_E2E_BUILD=1` (time and network): it
answers `build` and `y`, checks the built image against the contract, and that a second guided
`init` offers it as the default; the built image is removed at the end unless it existed before.
SKIP without `CONTROLLER_IMAGE` (unless `WARDEN_E2E_BUILD=1`).

## Directories

Resolved with the XDG base-directory rules (`$XDG_CONFIG_HOME`, `$XDG_STATE_HOME`,
`$XDG_DATA_HOME`, falling back to the defaults below). Created with mode 0700.

| Purpose | Default | Agent can write? |
|---|---|---|
| Config | `~/.config/warden/config.json` | No, never mountable |
| State | `~/.local/state/warden/` (`state.json`, `compose/`, `docker-config/`, `bin/`, `canary/`, `canary.lock`) | No: never mounted itself (see below) |
| Agent homes | `~/.local/share/warden/agents/<name>/` | Yes: mounted as the agent's `$HOME` |

- The state directory is never mounted. Only two kinds of path under it are: `<state>/bin/warden-<sha256>`
  (mode 0500, verified by hash after copying, mounted read-only, and only into the proxy and the
  canary, never the controller) and `<state>/canary/<random>/` (canary only, removed after every run).
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
internal/compose/      typed compose file, Render (the only producer of compose JSON) and Validate
internal/canary/       the in-container probe (warden probe), its output format, the canary project
internal/wardenbin/    copy and verify the warden binary under <state>/bin/
internal/netx/         the one way Warden opens a listener: MPTCP off (netx.Listen)
internal/gitinit/      the one host git run: git init in a folder Warden has just created
internal/refimage/     build the reference controller image, the image contract check, the build record
internal/termsafe/     strip control characters from untrusted output before it reaches the terminal
internal/controller/   compose generation, up/down/status/logs, post-start verification, RC URL
images/controller/     reference controller image (Dockerfile only)
images/                images.RuntimeImage, the embedded controller Dockerfile, and its contract test
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

The **runtime image** is the one stock image Warden's own containers (canary and proxy) run from,
with the `warden` binary mounted read-only: busybox, pinned by digest in code
(`images.RuntimeImage`), with no config field (since M7).

There is no UID field: the agent always runs as the invoking user's UID and GID, taken at runtime.
There is no field for privileged mode, capabilities, host namespaces, devices, extra mounts, ports
or the Docker socket. That is the point.

Validation (each rule has a failing test):
- unknown fields anywhere → error;
- a key that differs from a schema field only by case (`"Socket"`, or a Unicode case-fold like `"ſocket"`) → error; `encoding/json` would otherwise accept it;
- a duplicate key in any object, at any depth → error; `encoding/json` would otherwise let the last one win;
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
- The runner creates `<state>/docker-config` with mode 0700 if it is missing. It must be empty when
  the runner is created (a `config.json` can name credential helpers, a `cli-plugins/` can shadow
  `docker compose`); otherwise the runner fails with the exact fix. If it exists with
  looser permissions or another owner, the runner fails with the exact fix; it never changes
  permissions silently.
- argv only. Never `sh -c`.
- Every call has a timeout: 30 seconds by default; callers override it (`docker compose up`/`down`: 5 minutes).
  A caller overrides it by passing a context with a deadline.
- stdout and stderr are each capped at 16 MiB per call. Exceeding either stops docker and fails the
  call with an error; output is never silently truncated.

## Hardening (`internal/hardening`)

One function produces every container's security settings, with no exceptions in phase 1:
`user: <uid>:<gid>`, `cap_drop: [ALL]`, `no-new-privileges`, default seccomp, `read_only: true`
with a `tmpfs` for `/tmp`, memory, CPU and PID limits, and `init: true`.

A unit test asserts that no code path can produce `privileged`, any `cap_add`, `user` 0 or empty,
`pid`/`ipc`/`network: host`, `devices`, or a mount of the Docker socket.

Note: `read_only` may break an image that writes outside its mounts. If the controller image can't
run read-only, stop and ask; don't silently turn it off.

Precisely:

- `hardening.Settings(uid, gid, resources)` returns a typed set of compose service fields, and it is
  the only producer of them: `user: "<uid>:<gid>"` (UID 0 and GID 0 are refused), `cap_drop: [ALL]`,
  `security_opt: ["no-new-privileges:true"]`, `read_only: true`,
  `tmpfs: ["/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777"]` (exec allowed: the agent runs builds and
  tests from `/tmp`, and `noexec` adds nothing when the workspace is writable and executable),
  `mem_limit` and `memswap_limit` both the memory limit (no swap), `cpus`, `pids_limit`,
  `init: true`, and, so daemon defaults (`default-ipc-mode`, `default-cgroupns-mode`) can't weaken
  them, `ipc: private` and `cgroup: private`; `sysctls: {"net.mptcp.enabled": "0"}` when the
  host has MPTCP (MPTCP is a separate kernel protocol stack the agent has no use for; the sysctl is
  per network namespace, so each container gets it whatever the host has); plus `restart: "no"` and `pull_policy: never`.
  Seccomp and AppArmor are left at Docker's defaults, not named: naming `apparmor=docker-default`
  would stop containers starting on a host without AppArmor. The canary verifies both.
- MPTCP in Warden's own binary (see `DESIGN.md` §2, CVE-2026-98432): `go.mod` has
  `godebug multipathtcp=0`, so every listener and dialer defaults to plain TCP, and every listener
  Warden opens goes through `netx.Listen`, whose `net.ListenConfig` has `SetMultipathTCP(false)`
  explicitly: the proxy's (`warden proxy`) and the canary's `no-host` listener on the host. A test
  refuses any other listener in non-test code. Tests: the config reports `MultipathTCP() == false`;
  a client dialing with `SetMultipathTCP(true)` gets a connection whose `MultipathTCP()` is false
  (SKIP, never pass, where the kernel can't do MPTCP, which a control listener with MPTCP on shows);
  and the build info's `DefaultGODEBUG` contains `multipathtcp=0`.
- MPTCP: the goal is no MPTCP in the sandbox, and a kernel without MPTCP meets it, so Warden runs on
  one. `hardening.HostMPTCP` looks for `/proc/sys/net/mptcp` on the host: present, the sysctl is set;
  absent (`CONFIG_MPTCP` is built in, never a module, so the kernel has no MPTCP), no `sysctls` key
  at all; any other error fails closed. `compose.Validate` requires exactly the form that matches
  the host (`compose.Policy.MPTCP`). The field's type still can't express any other sysctl.
- Resources: the controller and the canary use `controller.resources`; the proxy uses constants,
  256 MiB, 0.5 CPU and 128 PIDs.
- Compose files are produced only by `compose.Render` (`internal/compose`), which marshals the typed
  file and then runs `compose.Validate` on the bytes it will hand to Docker. The typed service has no
  field for privileged mode, capabilities to add, devices, host namespaces, ports or arbitrary
  volumes. `Validate` checks the rendered JSON against an allowlist of keys and the exact hardened
  values above, refuses `user` 0 or empty, and refuses any bind mount whose source is, is inside, or
  contains the Docker socket. Each rule has a failing test.
- Every service runs with an explicit `entrypoint`, so an image's own entrypoint never wraps it.

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

Precisely:

- **Flags.** `--listen` (default `:3128`); `--allow <entry>`, repeated, at least one; `--ports`,
  comma-separated (default `443`), each 1 to 65535, no duplicates. Allow entries are validated with
  the same rules as `egress.allow` in the config, duplicates included: the proxy doesn't trust its
  flags because Warden wrote them. A bad flag is a usage error (exit 2). The `WARDEN_ROLE` check
  comes first.
- **Limits are constants, not flags:** 10 s to read the request headers, 8 KiB of headers (`net/http`
  adds its own small allowance on top), 5 s to resolve, a 10 s total dial budget with at most 5 s per
  address, and at most 256 concurrent tunnels. At the cap a request is refused at once, never queued.
  Writing a refusal to a slow client may take 25 s (header + resolve + dial budget, so the slowest
  502 or 504 still gets out); that deadline is cleared after `Hijack`.
- **Built on `net/http.Server`** with `Hijack` for the tunnel. Requests that `net/http` itself rejects
  before the handler runs (malformed request line, oversized or slow headers) get its own 4xx and no
  log line.
- **Target.** Only the CONNECT request target counts; it must be `host:port` with an explicit,
  canonical decimal port. The `Host` header is ignored. The host is lowercased and one trailing dot
  removed. IP literals are refused with their own reason before the allowlist: anything
  `netip.ParseAddr` accepts (including bracketed IPv6 and zones), and numeric forms resolvers may
  accept (`2130706433`, `0x7f.1`, `127.1`: the last label is all digits or `0x` hex). Anything else
  that isn't LDH labels is `invalid host`.
- **Leading dot.** `.claude.com` matches `claude.com` itself and every subdomain.
- **Order of checks:** method, target, port, IP literal, host syntax, allowlist, tunnel cap, resolve,
  address policy, dial. Every refused request gets `Connection: close`.
- **Status codes:** 405 not `CONNECT`; 400 malformed target or invalid host; 403 port, IP literal,
  host not allowed, or a non-public address; 503 at the tunnel cap; 502 the name doesn't resolve or
  every dial failed; 504 every dial timed out or the dial budget ran out.
- **Address policy.** IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unmapped and checked as IPv4. An address
  with a zone is refused. IPv4 is refused in: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`,
  `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`,
  `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`
  (which includes broadcast). IPv6 must be inside global unicast `2000::/3` (that alone refuses
  `::`, `::1`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, discard `100::/64`, ULA `fc00::/7`,
  link-local `fe80::/10`, site-local `fec0::/10` and multicast `ff00::/8`; each still gets its own
  reason) and outside `2001::/23` (IETF protocol assignments, including Teredo `2001::/32`),
  `2001:db8::/32` and `3fff::/20` (documentation) and 6to4 `2002::/16`. Anything that can't be
  classified is refused.
- **Mixed answers.** If a name resolves to any non-public address, the whole request is refused,
  even if other addresses are public. No addresses at all is a resolve failure.
- **Dialing.** The name is resolved once; the proxy dials `IP:port` only, never the name. IPv4
  addresses are tried before IPv6 (Docker bridge networks are IPv4-only by default), in resolver
  order within each family, each with its own 5 s timeout inside the 10 s total.
- **Tunnel.** The proxy writes the `open` log line, then `200 Connection Established`, then splices.
  Bytes the client sent after the request (already buffered by `net/http`) are forwarded first. Any
  read or write deadline left by `net/http` is cleared after `Hijack`. On EOF in one direction the
  other side gets `CloseWrite` (half-close); the tunnel ends when both directions are done. An error
  in either direction closes both sides. TCP keepalive stays on for both connections, so dead peers
  are still detected; there is no idle timeout.
- **Shutdown.** On SIGTERM or SIGINT the proxy stops accepting, closes every open tunnel, writes
  their `close` lines and exits 0.
- **Log lines.** One JSON object per line on stdout:
  `time` (RFC 3339, UTC), `id` (per-request counter, joins `open` and `close`), `event` (`start`,
  `open`, `close` or `deny`), `client`, `host`, `port`, `decision` (`allow`, `deny` or `error`),
  `reason`, `bytes_up` (client to server), `bytes_down`, `duration_ms`. Every field is present on
  `open`, `close` and `deny` lines. `host` is the normalized host once it parses, otherwise the raw
  target cut to 255 bytes. `open` is written only after a successful dial, and if it can't be written
  the tunnel is not opened (502). A request that is allowed but fails to resolve or dial is one
  `deny` line with `decision: error`. The `start` line carries `listen` (the bound address), `allow`
  and `ports`. Nothing from inside a tunnel is ever logged.
- **Reasons.** `open`: `allowlist: <entry>`, the entry that matched. `close`: `closed`, `shutdown`,
  `client to server: <error>` or `server to client: <error>`. `deny`: `method not allowed`,
  `invalid target: …`, `port not allowed`, `ip literal`, `invalid host`, `host not allowed`,
  `too many tunnels`, `shutting down`, `non-public address: …`, `resolve failed: …`,
  `dial failed …` or `dial timed out …`.
- Domain fronting is not checked (no SNI inspection); see `DESIGN.md` §2.

Proxy container: the runtime image, the `warden` binary bind-mounted read-only, command
`warden proxy --listen :3128 --allow … --ports 443`, `WARDEN_ROLE=proxy`, hardening from
`internal/hardening`, on both networks, container name `warden-proxy`.

Tests: allowlist matching (exact, subdomain, case, trailing dot, near-misses like
`evilapi.anthropic.com` and `api.anthropic.com.evil.org`), every deny path, private-address
refusal, a full tunnel against a local listener, and log lines for open and close. Tests inject a
resolver and a dialer: the resolver answers with well-known public addresses (`1.1.1.1`,
`2606:4700:4700::1111`; each use carries a comment saying why), and the dialer records the address
it was asked for and connects to a local listener. The address policy itself is never relaxed for
tests.

## Checks

Each check returns `{id, title, status: pass|warn|fail, detail, fix}`. `fix` is an exact command
or instruction for the user. Output is one table (or JSON with `--json`). Any `fail` → exit 1;
otherwise exit 0 (warnings don't change the exit code).

- Table: columns `STATUS ID DETAIL`, with the fix on an indented line below each failing or
  warning check. JSON: `{"ok": bool, "checks": [{id, title, status, detail, fix}]}`.
- A check that can't run because a check it depends on failed is itself a **fail**, with detail
  `not run: depends on <check id>`. Fail closed.

**Config**

| ID | Check | Fail or warn |
|---|---|---|
| config.valid | `config.json` exists and passes every config rule | fail, with each error |
| workspace.valid | The workspace passes mount validation | fail, naming the rule |

**Host**

| ID | Check | Fail or warn |
|---|---|---|
| host.not-root | Effective UID is not 0 | fail: "run Warden as your own user, not root or sudo" |
| host.os | Linux, amd64 or arm64 | fail |
| host.cgroup2 | `/sys/fs/cgroup/cgroup.controllers` exists | fail |
| host.docker-cli | `docker` found at a fixed path | fail |
| host.compose | `docker compose version --format json` exits 0 with a non-empty `version` | fail |
| host.docker-access | The configured socket is accessible to the user | fail, with the fix (add the user to `docker`, log in again); always also prints: "Docker socket access is root-equivalent on this host" |
| host.shared-mounts | No other container mounts the workspace or a Warden directory | fail, naming each container and mount, with the fix: stop that container or remove the mount |

`host.shared-mounts` works like this: list every container, running or stopped
(`docker ps -aq`), and `docker inspect` their mounts. For each bind mount, resolve the source
the same way mount validation resolves paths, and fail if it is, is inside, or contains the
workspace or any Warden directory (config, state, share). A named volume whose options are
`o=bind` (among its comma-separated `o` options) with a `device` path (`docker volume inspect`)
exposes a host path too and is treated exactly like a bind mount of `device`.

No container is skipped by name, label or compose project: those can be set by anyone with Docker
access. In milestone 2 nothing is skipped at all. Skipping Warden's own containers by the container
IDs Warden recorded (in state, and from the current canary run) arrives in milestones 4 and 6 (M6: see "Controller" below).
Unit tests use recorded `docker inspect` fixtures.

Version strings are compared by their leading `major.minor.patch` (distribution builds add
suffixes such as `2.40.3+ds1-0ubuntu1`). The engine, runc, containerd and Compose versions are
shown in check details and recorded in state; only the engine version can warn.

**Daemon** (parsed from `docker info --format '{{json .}}'` and `docker version --format '{{json .}}'`)

| ID | Check | Fail or warn |
|---|---|---|
| daemon.reachable | The configured socket answers | fail |
| daemon.mode | `SecurityOptions` has no `name=rootless` and no `name=userns` | fail: "not supported in v1" |
| daemon.cgroup | `CgroupVersion` is `2` | fail |
| daemon.seccomp | `SecurityOptions` has `name=seccomp` | fail |
| daemon.apparmor | `SecurityOptions` has `name=apparmor` | warn: weaker isolation |
| daemon.version | Server version recorded; warn if older than Docker Engine 25.0. The detail says whether the version is on the list of tested versions kept in the code (today: 29.1.3, verified live) | warn |
| daemon.pin | On `check`/`up`/`status`: daemon `ID` equals the pinned ID | fail: "daemon changed; re-run init" |

Parsing is tested against recorded `docker info` JSON fixtures: rootful, rootless, userns-remap,
cgroup v1, no AppArmor, unreachable.

**Canary** (`init` and `check` only)

- The runtime image is `images.RuntimeImage`, pinned by digest in code.
- Warden creates temporary `warden-canary-sandbox` (internal) and `warden-canary-egress` networks,
  starts a temporary proxy exactly as `up` would (allowlist from config), and starts the canary as the
  user's UID:GID with `hardening.Settings(...)` on the sandbox network, with a temporary directory from
  Warden's state directory bind-mounted. One probe prints `key=value` lines; Warden parses them.
  Everything is always removed, even on failure.

Precisely:

- `canary.image` checks that the runtime image is local (`docker image inspect`). Warden pulls
  it only in the guided `init`, on `y`; no service ever pulls
  (every service has `pull_policy: never`). The fix is `docker pull <ref>`, or `warden init` on a terminal.
- The canary runs only if every earlier check passed or warned; otherwise every `canary.*` check is
  `not run: depends on <first failed check>`. If setup fails, every remaining `canary.*` check fails
  with that error.
- **The probe is `warden probe`**, a hidden subcommand that refuses to run unless
  `WARDEN_ROLE=canary`. It runs from the same mounted binary as the proxy, so the runtime image needs
  no shell and no `nc`. It only reports what it observes; Warden decides on the host. Its output is
  strict: an unknown, missing or duplicate key fails the canary.
- **The binary.** `init` copies the running binary (`os.Executable`) to `<state>/bin/warden-<sha256>`,
  mode 0500, and verifies it by hash after copying; it must be a static ELF for the host's
  architecture (no `PT_INTERP`). `check` creates nothing: it verifies that copy for the running
  binary's hash, or fails with "run warden init".
- **A compose project**, `warden-canary`, rendered by `compose.Render` and passed on stdin
  (`docker compose -p warden-canary -f -`). Services `warden-canary-proxy` (both networks; the binary
  read-only at `/warden`; `warden proxy --listen :3128 --allow … --ports 443`; proxy limits) and
  `warden-canary` (sandbox network only; the binary read-only at `/warden` and
  `<state>/canary/<random>/mnt` read-write at `/canary`; `controller.resources`). The names differ
  from `up`'s, so the canary can run while Warden is up.
- **One canary at a time:** `init` creates `<state>/canary.lock`; `init` and `check` take an
  exclusive `flock` on it and fail at once if another run holds it. `check` fails with "run warden
  init" if it is missing.
- **Leftovers** from a crashed run (a container or network with a canary name) fail the canary
  with the exact `docker rm -f …` / `docker network rm …` fix. They are never removed automatically:
  anyone with Docker access can create a container with that name.
- **Sequence:** create (networks and containers, not started); read the sandbox network's gateway
  from `docker network inspect`; open the `no-host` listener; write the control file into the
  mounted directory; start; `docker wait warden-canary`; read both containers' logs; stat the
  owner file; tear down with `docker compose … down` (never `-v`), falling back to `docker rm -f`
  and `docker network rm` by the recorded IDs; remove `<state>/canary/<random>/`. A failure to
  remove anything is the `canary.cleanup` check, with the exact commands.
- **Timeouts:** 90 s for the whole canary, cleanup included; the probe waits up to 10 s for the
  control file and for the proxy port; each probe connection or lookup has 3 s.
- `host.shared-mounts` runs before the canary and the canary is gone afterwards, so nothing is
  skipped in M4.

| ID | Assertion |
|---|---|
| canary.image | The runtime image is local; never pulled by the canary |
| canary.caps | `CapEff` and `CapBnd` are `0000000000000000` |
| canary.nnp | `NoNewPrivs` is `1` |
| canary.seccomp | `Seccomp` is `2` |
| canary.uid | `Uid` and `Gid` (all four fields) equal the user's, and there are no supplementary groups other than the GID |
| canary.memory | `/sys/fs/cgroup/memory.max` equals the requested bytes and `memory.swap.max` is `0`. If `memory.swap.max` doesn't exist (no swap accounting in the kernel), it passes only if the host has no swap at all (`SwapTotal: 0 kB` in the host's `/proc/meminfo`), saying so in the detail; otherwise it fails with "cannot prove" |
| canary.pids | `/sys/fs/cgroup/pids.max` equals the requested limit |
| canary.cpu | `/sys/fs/cgroup/cpu.max` matches the requested quota (period 100000, quota within 0.1% of `cpus` × period) |
| canary.apparmor | `/proc/self/attr/current` is `docker-default (enforce)` (warn if the daemon has no AppArmor) |
| canary.rootfs | Writing to `/` fails with `EROFS` |
| canary.tmp | Writing to `/tmp` works, and `/tmp` is a `tmpfs` mounted `rw,nosuid,nodev` without `noexec`, `size=512m` and mode 1777 (the kernel omits `mode=` when it is 1777) |
| canary.mptcp | The probe opens an MPTCP socket (`socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`) and reads `/proc/sys/net/mptcp/enabled`. Host with MPTCP: the sysctl must be `0` and the socket must fail with `ENOPROTOOPT`. Host without: the sysctl must be absent and the socket must fail with `EPROTONOSUPPORT`. Anything else fails, including the host and the container disagreeing |
| canary.no-route | A TCP connection to `1.1.1.1:443` fails within 3 s. Control: Warden first dials it from the host; if the host can't reach it, the check fails with "cannot prove: host has no route to the control address" |
| canary.no-dns | The first allowlisted host doesn't resolve inside the sandbox. Control: the host must resolve it, or the check fails with "cannot prove" |
| canary.no-host | Warden listens on the sandbox network's gateway IP (from `docker network inspect`), on a random port, only while the probe runs; the canary's connection must fail and the listener must receive nothing. If the host has no such address (`EADDRNOTAVAIL`), it passes with "host has no address on the sandbox network". No port is ever open on the LAN |
| canary.proxy-allow | `CONNECT` to the first exact allowlist entry (or the domain of the first leading-dot entry) through the proxy returns `200` |
| canary.proxy-deny | `CONNECT` to `warden-canary.invalid` returns `403`, and the proxy logged `host not allowed` for it |
| canary.owner | A file the canary writes to the bind mount is owned by the user's UID and GID on the host |
| canary.cleanup | Every canary container, network and directory was removed |

## Reference controller image (`images/controller/Dockerfile`)

Built by the guided `init` from the copy compiled into the binary (see "Guided init"), or by the user, then referenced in config by image ID. It follows the
image contract in `DESIGN.md`:
- `debian:trixie-slim` base (Debian 13, the current stable release; bookworm is past its regular
  security support), pinned by digest (`sha256:f6b08b09…3ec4`, recorded on the operator's host on
  2026-11-02; the contract test refuses the all-zero placeholder); `ca-certificates`, `git`, `ripgrep`, `less`, `procps`;
- Claude Code installed **outside `$HOME`**;
- no `USER root` entrypoint, no firewall, no `iptables`: the image runs as whatever UID Warden passes;
- `HOME=/home/agent`, `WORKDIR /workspace`.

Open question to verify, not assume: whether Claude Code's native installer supports installing
outside `$HOME`. If it doesn't, stop and present the alternatives.

Answer (M5): it doesn't. `install.sh` downloads to `~/.claude/downloads` and runs `claude install`,
which puts the launcher and versions under `~/.local`; the script says "This installer puts
everything under $HOME". The alternatives are in the M5 pull request. **Decided in review:**
skip the installer and fetch the native binary itself, the way `install.sh` does, at a pinned
version, verified against a SHA-256 pinned in the Dockerfile (alternative A). We may switch later to
running the official installer at build time (alternative B), to keep a standard Claude Code install.

Precisely (decided in the M5 review):

- **Version:** the `stable` channel (today 2.1.309), not `latest`.
- **Claude Code** comes from `https://downloads.claude.ai/claude-code-releases/<version>/<platform>/claude`
  (the URL `install.sh` uses), through `ADD --checksum=sha256:<hex> --chmod=0755`, to
  `/usr/local/bin/claude`, owned by root. The version and one checksum per architecture (`linux-x64`,
  `linux-arm64`, from that version's `manifest.json`) are literals in the Dockerfile, so a build
  never trusts a manifest it fetched. One stage per architecture, selected by BuildKit's
  `TARGETARCH`; no `# syntax=` line, since that would pull a frontend image. Building needs BuildKit, which
  `docker build` uses only when the buildx plugin is installed (`docker-buildx` for Debian and
  Ubuntu's `docker.io`, `docker-buildx-plugin` for Docker's `docker-ce`); the legacy builder has no
  `ADD --checksum`, `ADD --chmod` or `TARGETARCH`. Warden itself doesn't need buildx. Updating means
  changing the version and both checksums and rebuilding.
- **No `curl` or installer script** in the image; `ca-certificates`, `git`, `ripgrep`, `less` and
  `procps` from Debian, with the apt lists removed.
- **`ENV HOME=/home/agent DISABLE_AUTOUPDATER=1`** (Warden sets `DISABLE_AUTOUPDATER` too; the image
  is safe on its own). `/home/agent` exists, root-owned 0755: Warden mounts the agent home over it.
- **`USER 65534:65534`** (nobody), so a plain `docker run` of the image isn't root. Warden always
  passes its own `user`.
- **No `ENTRYPOINT` or `CMD`.** Warden sets the entrypoint of every service; `claude` is on `PATH`.
- **A contract test** (`images/images_test.go`, standard library only) parses the Dockerfile and
  requires each rule above: the base pinned by digest, no `USER root` or `USER 0`, a final non-root
  `USER`, no firewall tools (`iptables`, `nft`, `ufw`), no `sudo`, `setcap` or setuid, no `curl` or
  `install.sh`, versioned download URLs with a checksum each, Claude Code outside `/home`, `HOME`,
  `WORKDIR`, `DISABLE_AUTOUPDATER`, and no `ENTRYPOINT`.
- **Live test** (`TestControllerImage`): if `CONTROLLER_IMAGE` is given to `scripts/e2e.sh` (an image
  ID or digest; it must be local, nothing is built or pulled), the image's config must have a
  non-root `User`, `HOME=/home/agent`, `WorkingDir` `/workspace` and no entrypoint. Then
  `claude --version`, `git --version`, `rg --version`, `less --version` and `ps --version` must
  each succeed with `--user <uid+1>:<gid+1> --cap-drop ALL --security-opt no-new-privileges
  --read-only --network none`, a 1777 tmpfs at `/tmp` and at `/home/agent`. Finally, without
  `--read-only`, `/usr/local/bin` and `/usr/local/bin/claude` must not be writable by that UID.
  Without `CONTROLLER_IMAGE` it reports SKIP. Containers follow the e2e rules: `warden-e2e-`
  names, `--rm`, recorded for the trap, never pulled.

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

Precisely (decided in the M6 review):

- **One proxy definition.** `controller.ProxyService` builds the proxy service; `up` and the canary
  both use it, so the canary's proxy is the one `up` runs by construction (only the names differ).
- **The controller service:** `entrypoint: ["claude"]`, `command: ["--remote-control", <name>]`
  (`entrypoint` is required in every service since M4; `claude` is on the image's `PATH`). The
  workspace bind is the path `mounts.ValidateWorkspace` resolved, never the configured string.
  `compose.Validate` allows `tty` and `stdin_open`, and only with the value `true`.
- **The proxy binary** is `init`'s verified copy, found with `wardenbin.Find`: `up` never installs
  it and fails with "run warden init" if it's missing.
- **`up` runs every check first, the canary included**, exactly as `check` does, read-only, before
  anything is shown: config, workspace, host and daemon checks, `daemon.pin`, `host.shared-mounts`
  (which is what catches a shared folder) and the canary. Any failure stops `up` with the check
  table. No canary result is ever recorded: a record could only say the sandbox was safe when it
  was recorded, and the kernel, AppArmor or the daemon can change before `up`. A canary takes about
  6 s on the operator's host, small next to the rest of `up`.
- **Before anything is shown**, after the checks: mount validation re-run; the binary copy
  verified; the agent home created (`agents/` and `agents/controller/`, 0700) or, if it exists,
  required to be a private directory of the user. `down`, `status` and `logs` check the pin too: a
  different daemon's containers mean nothing to Warden.
- **MPTCP status is three-state.** `hardening.MPTCP` is `MPTCPUnknown` (the zero value),
  `MPTCPPresent` or `MPTCPAbsent`; `hardening.HostMPTCP` returns one of the last two or an error.
  `hardening.Settings`, `compose.Validate` and the canary's evaluation refuse `MPTCPUnknown`, so a
  caller that forgets to set it fails instead of silently dropping the sysctl. `up` reads the
  host's status exactly as the canary does.
- **Last applied file.** `state.json` gains an optional `controller` object: `applied_compose`
  (the exact bytes applied, as a JSON string, so the diff compares bytes), `applied_at`,
  `proxy_id` and `controller_id` (full container IDs), `remote_control_url`, `url_found_at` and
  `incident`. `version` stays 1: optional fields are backward compatible. `init` keeps the object
  when it re-pins the same daemon and drops it when the daemon changes.
- **Approval.** `up` prints the generated file on stdout, then a line diff against the last
  applied file (unified style, 3 lines of context, `--- applied` / `+++ new`), or "first apply: no
  previous file", or "no changes since the last apply". Then `Apply? [y/N]` on stderr. It always
  asks, even with no changes. Anything but `y` exits 1 with "nothing applied".
- **Apply.** The shown bytes are written atomically to `<state>/compose/warden.json` (0600;
  `compose/` 0700) and passed to `docker compose -p warden -f <file> up -d` (5 minutes). The
  file, the time and both container IDs (`docker inspect --format '{{.Id}}'`) go into state right
  after `up -d` succeeds, before verification, so a later `check` or `down` knows them.
- **Post-start verification**, for `warden-proxy` and `warden-controller`:
  - `docker inspect --format '{{.State.Running}} {{.State.Pid}}'` must be `true` and a PID > 0;
  - that PID is `docker-init`; its children are found by reading `/proc/*/status` for `PPid`
    (no dependency on `CONFIG_PROC_CHILDREN`); there must be exactly one, waited for up to 10 s;
  - for both the init process and its child: `Uid` and `Gid` (all four fields) equal the user's;
    `CapEff`, `CapBnd`, `CapPrm` and `CapAmb` are zero; `NoNewPrivs` is 1; `Seccomp` is 2.
- **A verification failure is a security event: the evidence is kept.**
  - `docker compose -p warden -f <file> stop -t 0`, so the agent stops running at once.
  - `docker inspect` of both containers is saved to `<state>/incidents/<UTC time>.json` (0600;
    `incidents/` 0700).
  - The details and that path are printed, and `up` exits 1. The stopped containers stay in place,
    and state records the incident.
  - While an incident is recorded, `up` refuses, with the fix: inspect the containers and the
    incident file, then `warden down`. `down` removes the containers as usual and clears the
    incident.
- **Remote Control URL.** One function, `controller.FindURL`, on
  `docker logs --since <the container's .State.StartedAt> warden-controller`, so a URL from an
  earlier run can never match. Polled every 2 s for up to 60 s. ANSI escape sequences (CSI and OSC,
  including OSC 8 hyperlinks, whose target is kept) are removed before matching
  `https://claude\.ai/code/\S+`. The **first** match wins: Claude Code prints the URL at startup,
  before the agent does anything, and a later URL may be one the agent printed (the log is
  agent-influenced output). If `up -d` kept the recorded controller container (same ID) and a URL is
  recorded, that URL is kept and the log isn't read. If the controller stops running, the wait ends
  at once. Found: saved in state and printed.
- **No URL:** exit 1, the containers keep running, and the message says what to do: first run? log
  in with `docker attach warden-controller` (detach with Ctrl-P Ctrl-Q), then run `warden status`;
  or `warden down` to stop.
- **`status [--json]`:** the pin (if it fails: printed, exit 1, nothing else queried); for each of
  `warden-proxy` and `warden-controller`: state (or `not found`), image, start time, ID, and whether
  the ID is the one Warden recorded ("not started by Warden" otherwise); a recorded incident; the
  last URL and when it was found. If no URL is recorded and the recorded controller is running,
  `status` looks for one exactly as `up` does (one read, no wait) and records it, which is how the
  URL arrives after a first login. Containers not running is not a failure: exit 0.
- **`down`:** pin check, then `docker compose -p warden down` (5 minutes; never `-v`, never `-f`).
  The container IDs and any incident are cleared from state; the last applied file and URL are kept
  (the next `up` diffs against it; `status` shows the URL as the last one).
- **`logs proxy|controller [-n N]`:** pin check, then `docker logs --tail N <container>`, stdout and
  stderr passed through. A non-zero docker exit is exit 1.
- **`host.shared-mounts` and Warden's own containers.** A container whose full ID is recorded in
  state is skipped only if every one of its mounts is one Warden gave it: for the controller, the
  resolved workspace at `/workspace` and the agent home at `/home/agent`; for the proxy, a
  `<state>/bin/warden-<sha256>` copy at `/warden`. Any other mount on it is a finding as usual.
  Never by name or label.
- **Tests:** a golden file for the generated compose JSON
  (`internal/controller/testdata/warden.golden.json`, regenerated with `go test
  ./internal/controller -update`); `up`, `down`, `status` and `logs` end to end against the fake
  runner with a fixture `/proc`.
- **Live test** (`TestUpDown`): with `CONTROLLER_IMAGE` given to `e2e.sh`, `warden up` with `y`,
  post-start verification must pass, `check` must pass while up, `status` must show both running,
  then `warden down` must leave no `warden-*` container or network. The URL step needs a logged-in
  agent home, so the test only requires that `up` gets past verification. It reports SKIP without
  `CONTROLLER_IMAGE`, and also if any `warden-*` container or network already exists: `up` uses the
  real project name, so the test never touches a Warden that is up. Its containers are recorded
  for the script's trap and `down` always runs at the end.

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

## Live tests (`test/e2e`, `scripts/e2e.sh`)

Live tests run on the user's host, against the real daemon, at a reviewed commit. They are the
only tests that touch Docker. Only run them on commits that have been reviewed: the e2e binary runs
on the host with Docker access, which is root-equivalent.

- `test/e2e/` builds only with the build tag `e2e`.
- `scripts/e2e.sh <40-char commit SHA> [repo-url]` (default `https://github.com/rviscuso/warden`):
  refuses to run as root; refuses a branch name or short SHA, so the commit can't move between
  review and test; prints the SHA being tested.
- It creates a temp root under `${XDG_CACHE_HOME:-$HOME/.cache}` (outside `/tmp`, which mount
  validation forbids), with siblings `ws/`, `config/`, `state/` and `share/`, never nested, and
  deletes the whole root on exit, including on failure (`trap`).
- `TestCheckIsReadOnly` compares every path under the temp root before and after `check`: mode,
  size, owner and mtime. The one exception is the mtime of `<state>/canary` itself, which changes
  when the canary creates and removes its run directory; that directory must still be empty
  afterwards, with the same mode and owner.
- It clones the repo fresh into the temp root and checks out the SHA, and stops unless the script
  itself is byte-identical to that commit's `scripts/e2e.sh` (so the script that runs is the reviewed
  one, and knows what that commit's tests need), then builds and runs the unit
  tests in a Go container: image pinned by digest in the script (overridable with `GO_IMAGE`; tags
  refused either way), `--network none --user <uid>:<gid> --cap-drop ALL --security-opt
  no-new-privileges --read-only --tmpfs /tmp:exec --pids-limit 512 --memory 1g`, `GOCACHE` inside the
  temp root. It compiles the e2e test binary there, then runs it on the host as the normal user.
- E2e tests never change anything outside the temp root, with one exception: the
  `host.shared-mounts` test may `docker create` (never start) one container from the Go build image
  (already local), named `warden-e2e-<random>` with label `warden.e2e=1`, mounting the e2e
  workspace read-only, and always removes it (defer plus trap). Nothing is ever pulled: if the image
  isn't local, that test reports SKIP.
- The proxy live tests run the real `warden proxy` on the host, listening on `127.0.0.1`, and change
  nothing. The tunnel test first connects directly with TLS to `api.anthropic.com:443`: if that
  fails there is no network and it reports SKIP; if it works and the proxied connection fails, it
  fails. It also checks a deny and the log lines. The private-address test allows `localtest.me`, a
  public name that resolves to `127.0.0.1`, and expects the non-public-address refusal; if the name
  doesn't resolve only to loopback addresses at test time, it reports SKIP, never a pass.
- The canary live tests run `warden init` and `warden check` with the real canary, using
  the runtime image pinned in code (it must already be local), and
  check afterwards that no canary container, network or directory is left. A **negative control**
  runs `warden probe` in a deliberately unhardened `docker run` (no `--cap-drop`, no
  `no-new-privileges`, writable root, no `sysctls`, as another non-root UID and GID) and requires
  `canary.caps`, `canary.nnp`, `canary.rootfs`, `canary.uid` and, on a host with MPTCP, `canary.mptcp` to fail, so the canary is shown not to pass vacuously. These tests
  extend the exception above to their networks and containers, under the same rules: `warden-e2e-`
  or canary names, always removed, never pulled, SKIP if the image isn.t local.

## Milestones (one pull request each, reviewed before the next starts)

1. Skeleton: module, `cmd/warden`, `internal/cli` with help for every command, `version`, `internal/paths`, `internal/config`, `internal/mounts`, `internal/docker`.
2. Host and daemon checks (including `host.shared-mounts`), `config.valid` and `workspace.valid`, `init` (without canary) and `check`, state file with the daemon pin, root refusal, and the live-test harness (`test/e2e`, `scripts/e2e.sh`).
3. `internal/proxy` and `warden proxy`.
4. `internal/hardening` and the canary (uses the proxy).
5. Reference controller image in `images/controller/`.
6. Controller: `up` (with approval prompt, post-start verification and Remote Control URL), `down`, `status`, `logs`.
7. Guided `init` (interactive only on a terminal): workspace creation with `git init`, the runtime image pinned in code and pulled on approval, the reference controller image built from the binary on approval.
8. Claude sign-in on `up`, `warden login`, pre-seeded first-run settings, sign-in state in `status`.

## Done means

- `gofmt -l .` prints nothing; `go vet ./...` and `go test ./...` pass; `CGO_ENABLED=0 go build ./cmd/warden` succeeds.
- `go.mod` has no `require` lines.
- `warden --help` and every `warden <cmd> --help` print usage.
- Nothing is claimed as working against a real daemon. Real runs happen on the user's host, later.
