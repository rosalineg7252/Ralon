# Changelog

Versions follow the rules in `publishing.md`: while on `0.x` the minor is the
breaking position, and a change to what a policy protects is breaking even when
the CLI is untouched.

## 0.1.6

`agent.lock` becomes the thing that activates enforcement. Set the machine up
once with `ralon install`, and from then on a repository is protected because it
contains a policy file — no `ralon init`, no wrapper around the agent, nothing to
remember after a reboot, and repositories cloned later are covered by the same
setup.

Where that is not possible, this release says so instead of approximating it.
Linux gets a refusal with a reason; macOS gets a mechanism that is weaker than
`ralon run` and is labelled that way everywhere it appears.

### Added

- **`ralon install` / `ralon uninstall`** — registers a per-user background
  supervisor with the operating system: a Task Scheduler logon task on Windows, a
  launchd LaunchAgent on macOS. No administrator, no root, and it survives a
  reboot because the OS starts it. `--watch` names the directories to look for
  projects in; the default is the home directory.
- **`ralon pause` / `ralon resume`** — releases one project so its own policy can
  be edited, since `agent.lock` protects itself. A pause expires after fifteen
  minutes unless `--indefinitely` is given: a pause that is forgotten about is a
  project that stopped being protected without anyone deciding it should.
- **`ralon daemon`** — the supervisor itself, started by the service. `--once`
  does a single pass and prints what changed.
- **A macOS guard**, using `chflags uchg`. This **reverses an earlier decision**
  in this project not to implement it. The objection was to describing a
  narrowing as protection, and it was right; what changed is that a supervisor
  needs a mechanism it can *impose* on a process nobody started, and on macOS
  this is the entire list. So it is implemented and labelled: an agent can undo
  it with `chflags nouchg`, it does not pin ancestors, and it is not equivalent
  to process-level sandboxing. `ralon run` remains the guarantee there.
  `security.md` and `enforce/macos/immutable.rs` state the limits, and
  `tests/immutable.rs` asserts the weaknesses so the claims cannot drift.
- `ralon status` now answers "is the supervisor registered", "is it running" and
  "is *this project* protected" as three separate lines. The first two have a
  comfortable answer that means nothing about the third.
- `tests/supervisor.rs` — the full lifecycle against the real binary: a policy
  appearing and being removed, a malformed one, several repositories at once,
  twelve concurrent unrelated processes attacking, a supervisor restart, a
  simulated reboot, and writes attempted through shells and scripts rather than
  an agent's edit tools.

### Changed

- **`ralon install` fails on Linux**, with the reason and what to use instead.
  Every Linux mechanism is inherited by a process before it runs and cannot be
  applied to one already running, so a systemd user unit would start cleanly,
  report `active (running)`, and enforce nothing. `ralon run` is unchanged and
  remains stronger than any supervisor on any platform.
- `ralon guard` now resolves the backend a *guard* can use rather than the one
  `run` would pick. On macOS that is the difference between Seatbelt, which can
  only be inherited, and the immutable flag, which can be imposed.

### Fixed

- **A guard was reported as failed when it had actually started.** `guard
  --detach` waited three seconds for the background process to claim the project;
  a binary Windows has not scanned before takes about 2.9 seconds to reach its
  first instruction, which is the first run after every install and every
  upgrade. The wait is now thirty seconds, and the claim — a kernel object — is
  re-checked before any failure is recorded.
- **Two spellings of one directory were two projects.** The guard's claim is a
  hash of the project path, so a path reached by walking and the same path
  canonicalized did not refer to the same project. Workspace identity is now
  canonicalized where the path enters the system.
- Canonical Windows paths are no longer printed in their verbatim `\\?\` form.

### A note on the tests

The Windows attack helper in `tests/supervisor.rs` passes its command line to
`cmd.exe` with `raw_arg`. `Command::arg` escapes an embedded quote as `\"`, which
`cmd` does not parse that way, so a redirect to a quoted path silently never ran —
the attack did nothing, the file was unchanged, and reading it back looked like a
refusal. Every enforcement assertion would have passed against a Ralon that
enforced nothing. Caught because the tests also assert the control case: that the
same write *succeeds* before the policy is applied.

## 0.1.5

Enforcement is not the only thing that has to be legible. When Ralon refuses a
write, the message the developer or the agent actually reads is produced by
whatever attempted it — and `EBUSY: resource busy or locked` reads like a
corrupt file, not a policy. This release fixes the wording where Ralon owns it
and warns about it where Ralon does not.

### Changed

- **The hook now says "protected by Ralon"** rather than naming only the file
  it came from. This is the one refusal whose wording belongs to Ralon: without
  a hook the agent reports whatever its runtime made of the OS error — Node
  renders a Windows sharing violation as `EBUSY: resource busy or locked` —
  which reads as a broken file and sends the agent looking for a way around it
  rather than for something else to edit.
- **`init` and `guard --detach` say in advance what a refusal looks like**, in
  the spelling of the platform they are running on: `EBUSY` and `Access is
  denied` on Windows, `EPERM` on macOS, `EROFS` and `EACCES` on Linux. There is
  no interception point that would let Ralon rewrite those messages, so the
  honest move is to say once, before it happens, that the confusing error is
  the tool working.
- `init` closes with a link to the repository.

## 0.1.4

Ralon used to install cleanly on Windows and macOS, write a policy that looked
authoritative, confirm the paths were `locked`, and then enforce nothing —
while an agent edited those paths freely. Everything was behaving as designed
and documented, which is exactly what made it dangerous: the tool implied a
guarantee on platforms where it had none. This release closes that gap on
Windows with real enforcement, and everywhere else by saying so plainly.

### Added

- **macOS now enforces.** `agent.lock` is compiled to a Seatbelt profile and
  applied with `sandbox_init`, which is inherited across `exec` and by every
  descendant and cannot be left — the same shape as Linux, so `run` becomes the
  command and there is no supervisor to kill.

  It is the closest of the three platforms to the policy as written, because
  SBPL has `deny`. Nothing outside the named paths behaves differently (unlike
  Landlock, which must grant every sibling and leaves ancestors
  create-restricted), and a protected directory covers entries created inside
  it later (unlike the Windows locks, which need an ACL to reach that far).
  Ancestor directories are denied as nodes rather than subtrees, so they cannot
  be renamed away while their contents stay writable.

  The profile is generated by platform-independent code and unit-tested
  everywhere, and `run --dry-run --backend seatbelt` prints it on any machine —
  so what will be denied is reviewable without a Mac. The attack tables in
  `tests/enforcement.rs` now run against a real macOS kernel in CI with
  `RALON_REQUIRE_BACKEND=1`, which makes "nothing was tested" a failure.

  `sandbox_init` is deprecated and used anyway: it is what every sandboxed
  application on macOS uses, and the supported alternative is an entitlement on
  a signed `.app` bundle, which a CLI cannot be. `security.md` names it as a
  dependency rather than leaving it implied. A profile the kernel rejects is an
  error, never a warning — the command is not started.
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

  The protection lasts only as long as `run`, so the command is placed in a job
  object that dies with Ralon, closing the "kill the supervisor and keep
  writing" hole.
- **`ralon guard` — protection with no command to wrap.** `run` protects the
  agent it starts; a guard protects the ones it does not. It holds the same
  locks with nothing to supervise, and Windows refuses them to every process on
  the machine, so an agent launched from an IDE, an extension, another
  terminal, or installed next month is refused without knowing Ralon exists.
  `--detach` to leave one running, `--stop` to hand the files back, and
  `status` says which. Verified against unwrapped `cmd.exe`: overwrite, append,
  delete, rename, writing a protected file, rewriting the policy, and creating
  a new file in a protected directory — all refused, with no `ralon run`
  anywhere.

  This is possible on Windows precisely because its locks are *held* rather
  than inherited, and impossible on Linux for the same reason in reverse: a
  Landlock domain is applied to a process before it runs and cannot be imposed
  on one you did not start. `ralon guard` on Linux says that instead of
  pretending.
- **New files inside a protected directory are refused.** The gap the handles
  could not reach — creating an entry opens no existing object, so no share
  mode applies — is closed with a deny ACE, covering create, `mkdir`, copying
  or moving a file in, and renaming one inside. It is a *narrowing*, not a
  guarantee, and `security.md` is explicit about why: the agent owns the
  directory and an owner's `WRITE_DAC` cannot be denied, tested. Every ordinary
  create is refused; an agent that rewrites the ACL gets its write.

  The ACE is removed on exit. If Ralon is killed it stays, which fails closed;
  `status` reports it and `ralon guard --stop` clears it.
- `ralon init` now installs the agent hooks as well as writing the policy
  (`--no-hooks` to skip), and points at the one command that protects the
  project rather than leaving the reader to find it.
- **`ralon hook install`** — wires a refusal into an agent's own configuration
  instead of leaving each user to hand-write JSON. **Nine agents**, all by
  default, `--agent` to pick one: Claude Code, GitHub Copilot, OpenAI Codex,
  Cursor, Gemini CLI, Google Antigravity, Cline, Windsurf/Cascade and OpenCode.
  Existing settings and unrelated hooks are preserved; a settings file that
  cannot be parsed is never touched.
- `ralon hook check` makes the decision for all nine: one JSON document
  carrying every key they read — `permissionDecision`, `decision`/`reason`,
  `permission`/`agent_message`, `cancel`/`errorMessage` — plus exit code 2.
  Emitting a key an agent ignores costs nothing; omitting one it needs is an
  edit waved through.
- Paths are found under any spelling, at any depth, compared after lowercasing
  and dropping underscores — `file_path`, `filePath`, `TargetFile`,
  `AbsolutePath` are one entry, not four. Agents nest differently too, so
  Antigravity's `{"toolCall": {"name", "args"}}` is understood as well.
- **Reads are never refused.** Some agents call the hook for *every* tool
  rather than only for edits, so the check recognises a read and allows it.
  Without that, an agent would be refused permission to look at the very policy
  governing it. A tool name that is not recognisably a read is treated as a
  write, because the two mistakes are not equal.
- **JetBrains Junie and Roo Code are deliberately not installed.** Junie
  ignores project-local hooks by default, so the file would silently do
  nothing; Roo Code has no hook API yet, and its `.rooignore` blocks reads as
  well as writes. Both are covered by `run` and `guard` like everything else.
- None of this is needed where enforcement is running: `run` and `guard`
  restrict the *process*, so they already cover Aider, Amazon Q, Junie, Roo
  Code and anything shipped next year, hooks or no hooks.
- **An audit that runs before the agent does.** `status` and `run` now report
  conditions that weaken a policy without breaking it — and, on Windows, one
  that means the policy is naming the wrong thing: a protected file another
  program already holds open, such as a live database or a log a dev server
  appends to. It cannot be locked, so `status` warns and `run` refuses to start
  rather than reporting it as protected while it is not.

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
  landlock,sys}`, `enforce/windows/{locks,acl,job,guard}`,
  `enforce/macos/seatbelt`, `enforce/other` — with planning left
  platform-independent so `--dry-run` shows the same plan everywhere, and now
  the same Seatbelt profile too.
- **`rust-version` is 1.88, and true.** It said 1.79, which had not been
  buildable for some time: `clap_lex` requires edition 2024 and `globset`
  requires 1.88, so an older toolchain failed with a dependency's error instead
  of a clear message about this crate. Checked against 1.79, 1.85 and 1.88.
- `enforce_and_exec` returns the command's exit status instead of only an
  error. Linux still replaces the process and never returns; Windows has no
  inheritable restriction to hand over, so it supervises and reports back.
- The hook is one file per agent (`hook/{claude,copilot,codex,cursor,gemini,
  antigravity,windsurf,cline,opencode}.rs`), so supporting another is a new
  file rather than an edit to the policy logic. The three that share a
  settings-file shape share one installer rather than three copies drifting
  apart.

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
