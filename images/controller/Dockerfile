# Warden's reference controller image: Claude Code on Debian, for the image
# contract in DESIGN.md section 6. See docs/phase-1.md, "Reference controller
# image". images/images_test.go checks the rules below.
#
# Build it yourself, then put its ID in controller.image:
#   docker build -t warden-controller images/controller
#   docker image inspect --format '{{.Id}}' warden-controller
#
# Everything is pinned: the base by digest, Claude Code by version and one
# SHA-256 per architecture. To update Claude Code, take the version and the
# linux-x64 and linux-arm64 checksums from
#   https://downloads.claude.ai/claude-code-releases/<version>/manifest.json
# change all three below, and rebuild. Self-updating is off.
#
# No "# syntax=" line: that would pull a Dockerfile frontend image. ADD
# --checksum and --chmod need Docker's built-in BuildKit (Engine 25+).

# Debian 13 (trixie), the current stable release. PLACEHOLDER: replace the
# zeros with the digest of debian:trixie-slim (docker buildx imagetools
# inspect debian:trixie-slim). Until then the build fails, which is the
# point: the base is never a moving tag.
FROM debian:trixie-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS base

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git ripgrep less procps \
 && rm -rf /var/lib/apt/lists/*

# Claude Code 2.1.309 (stable channel), the native binary install.sh would
# fetch, outside $HOME and owned by root. One stage per architecture keeps the
# checksums literal; BuildKit builds only the one TARGETARCH selects.
FROM base AS claude-amd64
ADD --checksum=sha256:4d704a8aecbe038affa3000f498ae17c1b4f753add8facb8764120affc99b658 --chmod=0755 \
    https://downloads.claude.ai/claude-code-releases/2.1.309/linux-x64/claude /usr/local/bin/claude

FROM base AS claude-arm64
ADD --checksum=sha256:9796dd26899337f687739a0b39a7353b639f062a3436a7b941fcf19a1b757a9b --chmod=0755 \
    https://downloads.claude.ai/claude-code-releases/2.1.309/linux-arm64/claude /usr/local/bin/claude

FROM claude-${TARGETARCH}

# Warden mounts the agent home over /home/agent and the workspace over
# /workspace, and sets DISABLE_AUTOUPDATER itself too.
ENV HOME=/home/agent \
    DISABLE_AUTOUPDATER=1
RUN mkdir -m 0755 /home/agent
WORKDIR /workspace

# Never root, even for a plain docker run. Warden passes the user's UID:GID.
# No ENTRYPOINT or CMD: Warden sets the entrypoint of every service.
USER 65534:65534
