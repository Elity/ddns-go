# Fork image publishing and migration

These notes apply only to Elity/ddns-go. Upstream OIDC usage is documented in [OIDC.md](OIDC.md).

### Migration from earlier builds of this fork

Earlier experimental builds required local `allowedusers`/`allowedgroups`
rules. These fields and checks have been removed. **Move any restrictions to
the identity provider's policy for this client before upgrading.** Old YAML
keys are ignored and disappear on the next save. User/group restrictions are
not automatically transferred to a provider. Existing local passwords and
OIDC protocol configuration are preserved; restarting invalidates old sessions.

## Images and updates

The `OIDC image` workflow on `master` tests the code, runs the race detector and vet, then
publishes amd64/arm64 images to **GitHub Container Registry** (GHCR):

```sh
docker pull ghcr.io/elity/ddns-go:oidc
docker run -d --name ddns --network host --restart unless-stopped \
  -v /path/to/ddns-go:/root ghcr.io/elity/ddns-go:oidc
```

For reproducible deployments, pin `oidc-<full commit SHA>` and the digest. Keep
the previous container/image and back up the config before switching. When
rolling back, stop the new instance first so two DDNS writers never run against
the same configuration. Use container image updates, not upstream's binary
self-update, which would replace this fork's OIDC build.

```sh
go test ./...
go test -race ./web ./config
go vet ./...
docker build -f Dockerfile.oidc --build-arg VERSION=v6.17.7-oidc -t ddns-go:oidc .
```
