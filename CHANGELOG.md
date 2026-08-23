# Changelog

Versions follow the rules in `publishing.md`: while on `0.x` the minor is the
breaking position, and a change to what a policy protects is breaking even when
the CLI is untouched.

## 0.1.1

No change to what Ralon does or to what a policy means. This release exists so
there is one that was built and published by CI from a tagged commit, and to
claim the name on npm and PyPI with the same binaries.

### Distribution

- Prebuilt binaries for five targets, attached to the GitHub release with
  SHA-256 checksums. Linux builds are static musl, so they run anywhere,
  including containers with no glibc. `cargo binstall ralon` works.
- `npm install ralon` — the binaries wrapped as `ralon` plus five
  `@ralon/<platform>` packages, so npm downloads only the one that matches.
- `pip install ralon` / `uv tool install ralon` — the same binaries as wheels.
- A tag now publishes to all three registries after one manual approval.

### Packaging

- The crate tarball no longer carries the release plumbing (`npm/`,
  `packaging/`, workflows). Crate users still get `README.md`,
  `architecture.md`, `security.md`, `LICENSE` and the tests.

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
