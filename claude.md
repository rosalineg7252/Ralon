# Agent Lock — CLAUDE.md

## Project

Agent Lock is an open-source, framework-independent filesystem policy tool for AI-assisted development.

The project introduces a simple project-level file:

    agent.lock

The purpose of `agent.lock` is to declare files and directories that AI agents/processes are NOT allowed to modify.

The concept is intentionally similar to `.gitignore`:

    .gitignore  → tells Git what should not be tracked
    agent.lock  → tells Agent Lock what AI-controlled processes cannot modify

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

Crate `agentlock`, binary `agent-lock` — the crates.io name `agent-lock` was
already taken, and the command matches the `agent.lock` file it reads.

    src/
      main.rs cli.rs commands.rs   CLI, one function per subcommand
      policy.rs                    parse + validate agent.lock
      matcher.rs scan.rs           patterns → globs → paths on disk
      enforce/mod.rs               backend selection, Plan, ancestor pinning
      enforce/carve.rs             Landlock rule planning (pure, testable)
      enforce/linux.rs             the syscalls (the only unsafe code)
    tests/cli.rs                   CLI behaviour, every platform
    tests/enforcement.rs           real bypass attempts, Linux only

Commands: `agent-lock init | check | status | run`. `run` restricts the current
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

- `run` only compiles on Linux. Everything else builds and is tested on Windows
  and macOS too — keep it that way, `check`/`status` are used in mixed CI.
- Enforcement changes must be verified on Linux, not reasoned about:

      docker run --rm --security-opt seccomp=unconfined \
        -v "$PWD:/work" -w /work -e CARGO_TARGET_DIR=/tmp/target \
        rust:1-bookworm cargo test

  (`seccomp=unconfined` is what makes the mount backend available in a
  container; without it only Landlock is exercised.)
- A new bypass gets a failing test in `tests/enforcement.rs` first. The attack
  tables there are one line per attack and run against every available backend.
- Never let a failure to enforce be silent. If no backend is available, `run`
  refuses to start the command rather than running it unprotected.
- Policy semantics are the real API. A pattern that quietly stops protecting
  something is a breaking, security-relevant change.