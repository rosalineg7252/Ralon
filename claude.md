# Ralon — CLAUDE.md

## Project

Ralon is an open-source, framework-independent filesystem policy tool for AI-assisted development.

The project introduces a simple project-level file:

    agent.lock

The purpose of `agent.lock` is to declare files and directories that AI agents/processes are NOT allowed to modify.

The concept is intentionally similar to `.gitignore`:

    .gitignore  → tells Git what should not be tracked
    agent.lock  → tells Ralon what AI-controlled processes cannot modify

Example:

    my-project/
    ├── agent.lock
    ├── src/
    │   ├── index.tsx       🔒 protected
    │   ├── auth.ts         🔒 protected
    │   ├── App.tsx         ✏️ writable
    │   └── utils.ts        ✏️ writable
    └── tests/              ✏️ writable


## Core Principle

The developer writes `agent.lock`.

AI agents may READ `agent.lock`.

AI agents must NOT be able to MODIFY `agent.lock`.

AI agents must NOT be able to MODIFY resources declared by `agent.lock`.

There is deliberately:

- no GUI
- no password
- no account
- no cloud service
- no human approval workflow
- no framework dependency
- no dependency on Claude, Cursor, Codex, Gemini, etc.

The project must work independently of any specific AI agent.


# Example agent.lock

Minimal v1 syntax:

```yaml
version: 1

protect:
  - src/index.tsx
  - src/auth.ts
  - .env
  - config/**
  - .github/workflows/**
```


## Implementation

Rust, no runtime dependencies. `cargo build`, `cargo test`.

Crate and command are both `ralon`. The policy file stays `agent.lock` — it is
the format, and Ralon is one tool that enforces it, which is the point of being
agent-independent. Do not rename the file after the tool.

    src/
      main.rs cli.rs commands.rs   CLI, one function per subcommand
      policy.rs                    parse + validate agent.lock
      matcher.rs scan.rs           patterns → globs → paths on disk
      audit.rs                     conditions that weaken a policy
      hook/mod.rs hook/claude.rs   the agent hook; one file per agent
      enforce/mod.rs               backend selection, Plan, ancestor pinning
      enforce/carve.rs             Landlock rule planning (pure, testable)
      enforce/linux/               mount.rs landlock.rs sys.rs — the syscalls
      enforce/windows/             locks.rs acl.rs job.rs guard.rs — the Win32 calls
      enforce/profile.rs           Seatbelt profile text (pure, testable anywhere)
      enforce/macos/               seatbelt.rs immutable.rs guard.rs
      enforce/unguarded.rs         "a guard cannot work here", and why
      supervisor/mod.rs            reconcile() (pure) + the daemon loop
      supervisor/registry.rs       scan roots, remembered workspaces, the sweep
      supervisor/single.rs         one supervisor per user, claimed with a handle
      supervisor/watch/            windows.rs macos.rs sweep.rs — the notifications
      service/                     windows.rs macos.rs unsupported.rs — autostart
    tests/cli.rs                   CLI behaviour, every platform
    tests/enforcement.rs           real bypass attempts, Linux only
    tests/supervisor.rs            install → agent.lock → enforced; Windows + macOS
    tests/immutable.rs             what chflags uchg does and does not do; macOS only

Planning is platform-independent on purpose — `--dry-run` shows the same plan
on a machine that cannot enforce it — so only syscalls live under a platform
directory. A new platform is a new directory exposing `availability()` and
`enforce_and_exec()`; a new agent is a new file in `hook/`.

Commands: `ralon install | uninstall | scope add|list|remove | pause | resume |
daemon | init | check | status | hook install | guard | run`.

## The supervisor

`ralon install` registers a per-user background process with the OS — a Task
Scheduler logon task, a launchd LaunchAgent — that starts enforcement for any
project holding an `agent.lock`, under directories the developer named once.

It adds **no enforcement mechanism of its own**. It runs the lifecycle of
`enforce::guard`, so nothing about it is easier to bypass than `ralon guard` is,
and the supervisor itself contains no platform code. `reconcile()` is pure and
tested everywhere, on three inputs: what was recorded, what has a policy file,
and what the *kernel* says is actually enforced. The third is not redundant —
Windows enforcement dies with a reboot while the record still says `enforced`,
and a supervisor that trusted its notes would come up and protect nothing.

Discovery is a kernel watcher with a 60-second sweep behind it. The watcher is
the mechanism; the sweep is the correctness boundary, because a watcher reports
*changes* and has nothing to say about state that existed before it started. A
watcher that fails to start degrades to the sweep and says so.

`agent.lock` is a declaration and nothing more: relative patterns only, no PIDs,
sockets, absolute paths or daemon state, safe to commit, never written to. It
grants nothing by existing — only paths under a registered scan root are
considered, so a policy file inside a downloaded archive is inert.

Workspace identity is the canonical path, and that is load-bearing: the Windows
guard's claim is a hash of it, so two spellings of one directory are two projects
that cannot see each other.

Scopes are the directories a policy is honoured in, kept **disjoint** and
canonical by `Config::add`. Where Ralon is installed must never decide what it
protects — a home directory on `C:` says nothing about a repository on `D:`, and
`ralon scope add` is the answer rather than a wider default. `add`/`remove`
reconcile before returning; removal needs no release logic because the sweep
stops returning those workspaces and `reconcile` already ends them.

Two things about notifications, both learned from a bug: only `agent.lock` and
`config.yaml` may trigger a reconcile — a registration is recursive and
unfiltered, so anything else means reconciling on every write under `AppData` —
and the sweep runs on a deadline, not a timeout, so activity cannot starve it.

macOS `guard`/supervisor use `chflags uchg`, which **reverses** the earlier
decision recorded in `unguarded.rs` not to implement it. Keep it labelled as what
it is — a narrowing an agent undoes with `chflags nouchg`, not process-level
sandboxing, no ancestor pinning. `ralon run` is still the guarantee there.
`tests/immutable.rs` asserts the weaknesses on purpose, so the docs cannot drift
into a stronger claim.

Linux has no supervisor and `ralon install` refuses with the reason. Do not
"fix" this with a systemd unit: it would start, report `active (running)`, and
enforce nothing, which is worse than the refusal.

`run` restricts the current process and then `execve`s the command, so the
restriction is inherited by every descendant and there is no supervisor to
bypass. `guard` is the Windows-only inverse: it holds the locks with no command
to supervise, so it covers agents it did not start. That asymmetry is the
mechanism, not an oversight — Windows locks are *held* by a process and refused
to everyone else, Linux restrictions are *inherited* by a process and cannot be
imposed on one you did not start. Neither replaces the other, and `init` starts
neither: it writes a template nobody has edited yet, and a guard holding a
snapshot of that would protect the wrong paths convincingly.

macOS is one backend, **seatbelt** — the policy compiled to SBPL and applied
with `sandbox_init`. It is the only mechanism here that can say `deny`, so it
needs no carve-out and no ACL: protected directories cover what is created in
them later, and ancestors are denied as `literal` nodes so they cannot be
renamed while staying writable inside. Generating the profile is planning and
lives in `enforce/profile.rs`, tested on every platform; only `sandbox_init`
is under `macos/`. Nobody working on this repo can run it — verification is the
macOS CI job, which sets `RALON_REQUIRE_BACKEND=1` so a skipped test fails.

Two Linux backends, `auto` prefers the first:

- **mount** — read-only bind mounts in a user + mount namespace, locked by
  entering a second namespace. Ancestor directories are pinned as mount points
  so none of them can be renamed out from under a protected path.
- **landlock** — the LSM, for environments without user namespaces. Landlock
  rules are *additive*, so "everything except this file" is expressed by
  granting every sibling along the way; the cost is that directories leading to
  a protected path accept no new entries.

See `architecture.md` for how and why, `security.md` for the threat model and
the tested limitations, `publishing.md` for release steps.


## Working on this repo

- Everything compiles on every platform; only the syscalls are Linux-gated.
  `check`, `status` and `hook install` are used in mixed CI — keep them working
  there.
- Enforcement changes must be verified on Linux, not reasoned about:

      docker run --rm --security-opt seccomp=unconfined \
        -v "$PWD:/work" -w /work -e CARGO_TARGET_DIR=/tmp/target \
        rust:1-bookworm cargo test

  (`seccomp=unconfined` is what makes the mount backend available in a
  container; without it only Landlock is exercised.)
- macOS cannot be verified locally by anyone here — there is no container for
  it. Changes to the Seatbelt backend are checked by the macOS CI job, and the
  half that *can* be checked anywhere (the profile text) is unit-tested, so a
  change lands with `--dry-run --backend seatbelt` output in the PR and a green
  macOS job, not with a description of what it should do.
- **Type-check macOS before pushing**, even though it cannot be run:

      rustup target add aarch64-apple-darwin
      cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings

  `cargo check` needs no Apple SDK, so this works from Windows or Linux and is
  not optional. The `immutable` backend shipped with `chflags` typed as
  `c_ulong`, which compiles on every platform except the one it runs on; this
  caught it before CI did.
- A new bypass gets a failing test in `tests/enforcement.rs` first. The attack
  tables there are one line per attack and run against every available backend.
- **Assert on the filesystem, never on an exit code.** `del` returns 0 when it
  failed, `>` returns 0 when it was refused, and `SetEntriesInAcl` returned
  `ERROR_SUCCESS` while changing nothing. Two bugs here were "attack refused"
  reported by a check that never looked at the file. Read the file back.
- Never let a failure to enforce be silent. If no backend is available, `run`
  refuses to start the command rather than running it unprotected — and says
  what to do instead, because "unavailable" on its own lets the reader conclude
  the policy is protecting them when nothing is.
- Weaknesses enforcement cannot fix — a hard link to a protected file, a second
  mount of the project — are reported by `audit.rs` before the agent starts.
  A new one means a warning *and* an entry in `security.md`.
- Policy semantics are the real API. A pattern that quietly stops protecting
  something is a breaking, security-relevant change.