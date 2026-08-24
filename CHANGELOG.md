# Changelog

Versions follow the rules in `publishing.md`: while on `0.x` the minor is the
breaking position, and a change to what a policy protects is breaking even when
the CLI is untouched.

## 0.1.2

The first release to reach npm and PyPI. No change to what Ralon does: `0.1.1`
published to crates.io, but the npm and PyPI configuration could only be fixed
by releasing again, because the packaging scripts are read from the tag.

- `npm install -g ralonlock` — the binaries wrapped as `ralonlock`, plus five
  `@stoneware-dev/<platform>` packages so npm downloads only the one that
  matches. Neither `ralon` nor `@ralon` was available: npm refuses the first as
  too similar to the existing `raven`, and the second scope was taken.
- `pip install ralonlock` / `uv tool install ralonlock` — the same binaries as
  wheels.
- The command is `ralon` however it was installed. Only the crate kept the
  name.
- Release workflow actions moved to their Node 24 versions, and the npm step
  skips versions that are already published, so a partial failure can be
  re-run instead of costing a version.

## 0.1.1

Published to crates.io, with prebuilt binaries on the GitHub release. No change
to what Ralon does or to what a policy means; this is the first release built
and published by CI from a tagged commit.

### Distribution

- Prebuilt binaries for five targets, attached to the GitHub release with
  SHA-256 checksums. Linux builds are static musl, so they run anywhere,
  including containers with no glibc. `cargo binstall ralon` works.
- A tag publishes to all three registries after one manual approval.

### Packaging

- The crate tarball no longer carries the release plumbing (`npm/`,
  `packaging/`, workflows). Crate users still get `README.md`,
  `architecture.md`, `security.md`, `LICENSE` and the tests.

### Fixed

- The musl targets did not compile: `libc::ST_*` is defined only for glibc, so
  the flags read back before a read-only remount are now spelled out from the
  kernel's own values. No effect on behaviour — glibc builds were identical —
  but without it there are no static Linux binaries. CI now compiles the musl
  target on every push.

## 0.1.0

First release. Published by hand from a working tree with uncommitted changes,
so it corresponds to no commit in the repository; `0.1.1` is identical in
behaviour and reproducible.

### Added

- `agent.lock`: a YAML policy declaring paths AI agents may not modify.
  `agent.lock` protects itself. Patterns are relative to it; `..`, absolute
  paths, `~` and `!` are rejected rather than reinterpreted.
- `ralon run -- <command>` restricts the current process and `exec`s the
  command, so the restriction is inherited by every descendant and cannot be
  dropped. Two Linux backends:
  - **mount** (default) — read-only bind mounts in a user + mount namespace,
    locked by entering a second namespace. Ancestor directories are pinned as
    mount points, so none can be renamed out from under a protected path.
  - **landlock** — the LSM, for hosts without user namespaces. Landlock rules
    are additive, so "everything except this file" is expressed by granting
    every sibling along the way; the cost is that directories leading to a
    protected path accept no new entries.
- `ralon init`, `check`, `status`, and `run --dry-run`. `check` exits 1 for a
  protected path, which is enough to drive an agent's pre-write hook.
- `init`, `check` and `status` work on Windows and macOS; only `run` needs
  Linux.

### Security

- Enforcement is verified by `tests/enforcement.rs`, which attempts real
  bypasses — overwrite, append, truncate, delete, rename away, rename over,
  delete-and-recreate, hard link, symlink, chmod-then-write, parent rename,
  `umount`, bind-mount-around, nested namespaces — against a live sandbox, for
  every backend the kernel provides.
- Known limitations are documented in `security.md`. The one to know: both
  backends are path-based, so a second pre-existing mount of the same directory
  is not covered.
- If no backend is available, `run` refuses to start the command rather than
  running it unprotected.
