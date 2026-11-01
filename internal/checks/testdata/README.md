# Check fixtures

Fixtures hold only the fields Warden reads, with obviously fake identifiers. `@ROOT@` is replaced
at test time with the test's temporary directory.

| File | Provenance |
|---|---|
| `docker-info-rootful.json` | Recorded on a real rootful host (Docker Engine 29.1.3, Ubuntu `docker.io`), trimmed; ID replaced with zeros |
| `docker-info-rootless.json`, `-userns.json`, `-cgroupv1.json`, `-no-apparmor.json` | Derived from the rootful recording, changing only the field under test |
| `docker-info-unreachable.json` | Derived (not recorded): the shape `docker info` prints with `ServerErrors` |
| `docker-version.json` | Recorded on the same host, trimmed to `Server.Version` and `Components` |
| `compose-version.json` | Recorded on the same host (Compose 2.40.3, Ubuntu `docker-compose-v2`), verbatim |
| `docker-inspect-shared.json`, `docker-volume-inspect.json` | Derived from Docker's documented inspect format (not recorded) |
