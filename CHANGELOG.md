# Changelog

Versions follow the rules in `publishing.md`: while on `0.x` the minor is the
breaking position, and a change to what a policy protects is breaking even when
the CLI is untouched.

## 0.1.4

Ralon used to install cleanly on Windows and macOS, write a policy that looked
authoritative, confirm the paths were `locked`, and then enforce nothing —
while an agent edited those paths freely. Everything was behaving as designed
and documented, which is exactly what made it dangerous: the tool implied a
guarantee on platforms where it had none. This release closes that gap on
Windows with real enforcement, and everywhere else by saying so plainly.

### Added

- **Windows now enforces.** `ralon run` holds every protected file open with a
  share mode that allows readers and refuses writers, so writing, deleting,
  renaming or replacing one fails with a sharing violation — for **every
  process on the machine**, whichever agent it belongs to and whether or not
  that agent supports hooks. Verified against the same attack battery the Linux
  backends face: overwrite, append, delete, rename away, replace by copy or
  move, rename the parent directory, write inside a protected directory, remove
  the tree, rewrite the policy, and clear the read-only attribute first. All
  refused; ordinary edits elsewhere unaffected.

  ACLs were the obvious approach and are the wrong one: the agent runs as the
  same user, so any permission Ralon can set it can unset. A handle is not a
  permission.

  Two limits, documented in `security.md` and both tested: a *new* file created
  inside a protected directory is not covered, and the protection lasts only as
  long as `run` — so the command is placed in a job object that dies with
  Ralon, closing the "kill the supervisor and keep writing" hole.
- **`ralon hook install`** — wires a refusal into an agent's own configuration
  instead of leaving each user to hand-write JSON. Covers **Claude Code**
  (`.claude/settings.json`), **Cursor** (`.cursor/hooks.json`) and **OpenCode**
  (`.opencode/plugins/ralon.js`), all three by default, `--agent` to pick one.
  Existing settings and unrelated hooks are preserved; a settings file that
  cannot be parsed is never touched.
- `ralon hook check` makes the decision for every agent: one JSON document
  carrying both Claude's and Cursor's keys, plus exit code 2, which all three
  read as "blocked". Paths are found under any of the spellings agents use
  (`file_path`, `filePath`, `path`, …) at any depth, because one unrecognised
  key is an edit waved through.
- On Linux none of this is needed: `ralon run` restricts the *process*, so it
  already covers Codex, Antigravity, GLM, Gemini and anything shipped next
  year, hooks or no hooks.
- **An audit that runs before the agent does.** `status` and `run` now report
  conditions that weaken a policy without breaking it.

### Security

- **A pre-existing hard link to a protected file bypasses both backends.** The
  other name is an ordinary file: not bind-mounted, not carved out of the
  Landlock grant, and writing it changes the protected file. Verified against a
  live kernel — a write through the second name changed `.env` inside the
  sandbox. Ralon now warns when a protected file has more than one link. This
  was previously undocumented.
- **A second mount of the project bypasses both backends**, which
  `security.md` already documented. Ralon now detects it by reading
  `/proc/self/mountinfo` and names the other path.
- `run` and `status` no longer report "unavailable" and stop there. They say
  plainly that nothing is protecting those paths, and what to do instead.

### Changed

- Enforcement is split one directory per platform — `enforce/linux/{mount,
  landlock,sys}`, `enforce/windows/{locks,job}`, `enforce/macos`,
  `enforce/other` — with
  planning left platform-independent so `--dry-run` shows the same plan
  everywhere. macOS documents the mechanism it would use (Seatbelt) rather
  than standing empty.
- `enforce_and_exec` returns the command's exit status instead of only an
  error. Linux still replaces the process and never returns; Windows has no
  inheritable restriction to hand over, so it supervises and reports back.
- The hook is one file per agent (`hook/{claude,cursor,opencode}.rs`), so
  supporting another is a new file rather than an edit to the policy logic.
  Codex, Antigravity, GLM and Gemini are not included: none of them documents a
  hook that can refuse a file edit before it happens, and shipping a config
  that silently does nothing would be worse than shipping none.

## 0.1.3

### Fixed

- **`npm install ralonlock` was unusable in 0.1.2**: every invocation failed
  with `EACCES`. GitHub Actions artifacts do not preserve file permissions, so
  the npm job packed a binary with the executable bit already stripped. The
  packager now sets it explicitly, and the shim repairs an install that has the
  problem instead of failing. Only npm was affected — the release archives are
  built where the binary is compiled, and the wheels set the mode themselves.
- `dist/` and `artifacts/` are ignored by git and excluded from the crate
  tarball. Packager output had been committed, and would have shipped to
  `cargo install` users.

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
