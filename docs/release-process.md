# Release process

The legacy `lenso-module-notification` release line remains available through
its historical crate versions and tags. The default branch now owns five vNext
packages with distinct identities:

1. `lenso-capability-email-dispatch`;
2. `lenso-capability-notification-admin`;
3. `lenso-capability-notification-delivery`;
4. `lenso-capability-notification-transactional`; and
5. `lenso-notification-plugin`.

Transactional descriptor `1.1.0` is an additive release in the existing
`lenso.notification.transactional@1` series: existing invitation Providers and
consumers must regenerate before they claim the new Plugin package version,
while the Capability identity and existing operation meanings remain stable.

Publication is manual and runs only from a clean `main` checkout through
`.github/workflows/release-plz.yml`. Pushes to `main` may create or update a
release pull request, but never publish. A live dispatch requires `live=true`,
`confirm=publish`, and the `main` ref. Run the dry-run dispatch first.

Before first publication of each new crate name:

1. pass generated-contract, Rust, PostgreSQL, Console, and independent package
   verification;
2. allocate the crate name once using crates.io's authenticated initial-publish
   flow, because OIDC Trusted Publishing cannot create a new crate name;
3. configure the crate's Trusted Publisher with owner `LioRael`, repository
   `lenso-notification-plugin`, workflow `release-plz.yml`, and no environment;
4. confirm all four Capability crates are public before the implementation
   crate; and
5. run the live workflow only after every crate has its matching publisher.

`lenso-notification-plugin` additionally depends on
`lenso-capability-notification-template` version `0.1.0`, with development
source locked to Template repository commit
`c07d56a5caecd173916ea3fa5b094f78e1d00648`. Publish that Capability version
before publishing this implementation crate; Cargo's normalized public manifest
resolves the version from crates.io and does not retain the Git source.

`scripts/check-public-packages.sh` packages each Capability, creates the Plugin
archive with exact source patches for coordinated unpublished changes, including
the lock-resolved Template Capability source, then
extracts the normalized archives and runs check/test/clippy against those bytes.
It prevents a workspace path dependency from being silently replaced by an
older registry Capability during package verification.

The workflow has no registry-token fallback. The live job obtains a short-lived
crates.io credential through GitHub OIDC and has only the required
`id-token: write` publication authority. Never use `--no-verify`, a long-lived
registry token, or a Git dependency as a publication shortcut.
