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
      enforce/macos/ windows/      no backend yet; each documents its mechanism
    tests/cli.rs                   CLI behaviour, every platform
    tests/enforcement.rs           real bypass attempts, Linux only

Planning is platform-independent on purpose — `--dry-run` shows the same plan
on a machine that cannot enforce it — so only syscalls live under a platform
directory. A new platform is a new directory exposing `availability()` and
`enforce_and_exec()`; a new agent is a new file in `hook/`.

Commands: `ralon init | check | status | hook install | run`. `run` restricts the current
process and then `execve`s the command, so the restriction is inherited by every
descendant and there is no supervisor to bypass.

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
- A new bypass gets a failing test in `tests/enforcement.rs` first. The attack
  tables there are one line per attack and run against every available backend.
- Never let a failure to enforce be silent. If no backend is available, `run`
  refuses to start the command rather than running it unprotected — and says
  what to do instead, because "unavailable" on its own lets the reader conclude
  the policy is protecting them when nothing is.
- Weaknesses enforcement cannot fix — a hard link to a protected file, a second
  mount of the project — are reported by `audit.rs` before the agent starts.
  A new one means a warning *and* an entry in `security.md`.
- Policy semantics are the real API. A pattern that quietly stops protecting
  something is a breaking, security-relevant change.