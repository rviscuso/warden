# Working on Warden

Read `DESIGN.md` and the current phase spec in `docs/` before writing code.

## The operator reviews every line

Ron reviews every PR and must be able to explain every design decision in an interview.
- When there are two reasonable designs, describe both with trade-offs in the PR and ask. Don't pick silently.
- Explain each non-obvious choice in one line in the PR description.
- If the spec is ambiguous or looks wrong, stop and ask. Don't guess.

## Code rules

- Go standard library only. `go.mod` must have no `require` lines. Never add a dependency.
- Exec with argv only. Never `sh -c`, never string-built commands.
- Fail closed: if a check can't run or can't prove its result, it fails.
- Never weaken a check, a validation rule or a hardening setting to make a test pass.
- Container hardening comes only from `internal/hardening`.
- Don't read `DOCKER_HOST`, `DOCKER_CONTEXT` or other Docker environment variables.
- No secrets, host names, IP addresses or personal paths in code, tests or docs. This repo is public.

## Workflow

- Small commits, one concern each. Tests ship with every change.
- Before every commit, run and paste the output: `gofmt -l .`, `go vet ./...`, `go test ./...`.
- Report results faithfully. Never claim something works against a real Docker daemon; there is none here.
- Push only to branches named `agent/<topic>`. Never push to `main`.
- Never edit `.github/workflows/` (pushes that do are rejected).
- Open a PR with the GitHub API, for example:
  ```
  curl -fsS -X POST https://api.github.com/repos/rviscuso/warden/pulls \
    -H "Authorization: Bearer $(cat /run/secrets/gh_token)" \
    -H "Accept: application/vnd.github+json" \
    -d @pr.json
  ```
  Write `pr.json` with `title`, `head`, `base: "main"` and `body`. Never print the token.
- The PR body lists: what changed, design choices and why, test output, and open questions.

## Environment

- Go is installed; `GOPROXY=off`, so nothing downloads. `/tmp` is noexec; `GOTMPDIR` handles `go test`.
- No Docker socket in this container, by design.
