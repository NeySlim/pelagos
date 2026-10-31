# Releasing Pelagos

1. Write `docs/releases/X.Y.Z.md` (starts with `# Pelagos X.Y.Z`) and a `## X.Y.Z` section in `CHANGELOG.md`, then `make release VERSION=X.Y.Z`: it runs `scripts/release-check.sh`, commits `chore(release): X.Y.Z` with the notes, tags `vX.Y.Z` and opens the next `.dev0`.
2. `git push origin main vX.Y.Z`: the `release` workflow runs the full CI, builds and tests the debs (amd64, arm64 on native runners) and the rpms (el9, el10) of the tag, runs the blocking checks, drafts the GitHub release (tested packages, `release.json`, `NOTES.md`, `SHA256SUMS`) and pushes the tested images to ghcr.io (`X.Y.Z`, `latest`).
3. Review the draft on GitHub, then click **Publish**: nothing publishes it by itself. A failed or repeated run (Actions, `release`, Run workflow with the tag) replaces the draft's files.
4. Production takes those same files: `scripts/deploy-prod.sh --tag vX.Y.Z --dry-run ns2 ns1`, then without `--dry-run` (it downloads the draft or release with `gh`, checks `SHA256SUMS` and `release.json`, standby first).
5. Final versions only (`vX.Y.Z`: GitHub renames asset names with `~`); `make release NO_TAG=1 VERSION=X.Y.Zrc1` builds local debs of `HEAD` for lab tests, never for production. Optional signing: repository secret `PELAGOS_RELEASE_KEY` (Ed25519 private key PEM, `PELAGOS_RELEASE_KEY_PASSWORD` if any).
