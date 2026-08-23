# Ralon

A file in your project says what AI agents may not touch:

```yaml
# agent.lock
version: 1

protect:
  - src/index.tsx
  - src/auth.ts
  - .env
  - config/**
  - .github/workflows/**
```

Then you start the agent through it:

```console
$ ralon run -- claude
ralon: 5 paths locked via the mount backend
```

Inside that process — and every process it spawns, forever — those paths are
read-only *to the kernel*. Not a linter, not a hook the agent can talk its way
past, not a prompt it can forget. `open()` returns `EROFS`, `rm` returns
`EACCES`, and the agent gets on with the work it is allowed to do.

```
.gitignore  → what Git must not track
agent.lock  → what AI-controlled processes must not modify
```

Deliberately absent: no GUI, no account, no cloud service, no approval workflow,
no dependency on Claude, Cursor, Codex, Gemini or any other tool. It is a
binary, a config file, and two kernel features.

## Install

```console
$ cargo install ralon
```

The policy file is called `agent.lock`, not `ralon.lock`, on purpose: it is a
format, not a product. Anything could enforce it — this is one thing that does.

Or from a checkout:

```console
$ cargo install --path .
```

The `run` command needs Linux. `init`, `check` and `status` work everywhere, so
policies stay checkable in CI and on a laptop of any kind.

## Use

```console
$ ralon init                   # write a starter agent.lock
$ ralon status                 # what is protected, and what this kernel can enforce
$ ralon check src/auth.ts      # is this path protected? exits 1 if it is
$ ralon check                  # list everything the policy protects right now
$ ralon run --dry-run -- npm test    # what would be locked, without locking it
$ ralon run -- claude          # the real thing
```

`ralon run` replaces itself with your command, so the agent keeps its
terminal, its exit code, and its signals. There is no supervisor process to kill
and nothing to keep running in the background.

### As a pre-write hook

`check` exits 1 when a path is protected, which is enough for any agent that
supports hooks. For Claude Code, in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Write|Edit",
      "hooks": [{ "type": "command", "command": "ralon check \"$CLAUDE_FILE_PATH\" >/dev/null || exit 2" }]
    }]
  }
}
```

That is a courtesy, not a defence: it produces a clear error instead of a
confusing `EACCES`. The kernel is what actually stops the write, and it stops
`sed -i`, `python`, and `git checkout` too.

## The policy file

```yaml
version: 1          # required, must be 1

protect:            # paths relative to agent.lock
  - .env            # a file
  - config          # a directory, and everything under it
  - config/**       # the same thing, spelled out
  - src/*.ts        # * stops at /
  - "**/secrets.json"   # ** does not
```

- `agent.lock` protects itself. An agent that can rewrite the policy has no
  policy.
- Patterns are relative to the policy file. `..`, absolute paths, `~` and `!`
  are rejected rather than quietly reinterpreted.
- Any command finds the policy by walking up from the working directory, the
  same way `git` finds `.git`.

## What the guarantee actually is

Under `ralon run`, for every protected path, in the sandboxed process and
all of its descendants:

| Attempt | Result |
| --- | --- |
| write, append, truncate, `cp` over it | denied |
| delete it, rename it away | denied |
| replace it by renaming another file over it | denied |
| create files inside a protected directory | denied |
| rename or remove a directory on the way to it | denied |
| read it | allowed |
| everything else in the project | untouched |

These are the cases in `tests/enforcement.rs`, which runs the attacks for real
against a real sandbox and then checks the file from outside it.

The restriction is inherited across `fork` and `exec` and cannot be dropped: a
Landlock domain is one-way, and the mount namespace is locked before your
command starts, so `umount` and bind-mount tricks fail from inside.

### Where it stops

- **Only what you launch.** A policy protects the processes started through
  `ralon run`. An agent started some other way is not restricted — the
  point is that you start it this way.
- **Only what exists.** A protected path that is not on disk yet cannot be
  bind-mounted. `status` and `run` warn about patterns matching nothing. (Under
  the landlock backend such paths cannot be created at all, which is stricter.)
- **Not against root.** A process that can become root outside the namespace can
  undo anything. This defends against an agent doing something stupid or
  overreaching, not against an attacker with your password.
- **Not a secret store.** Protected files stay readable. `agent.lock` says what
  must not *change*; if a file must not be *read*, do not put it in the project.

## Backends

`run` picks the strongest backend the kernel offers. `ralon status` shows
what is available, and `--backend mount|landlock` pins the choice.

**mount** (default) — read-only bind mounts inside a user + mount namespace,
locked by entering a second namespace so they cannot be undone. Every parent
directory of a protected path is turned into a mount point too, so no directory
on the way to it can be renamed or removed. Precise: nothing outside the
protected paths behaves differently. Needs unprivileged user namespaces, which
some hardened distros and container runtimes disable.

**landlock** — the kernel LSM, Linux 5.13+. Needs no namespaces, so it works
where user namespaces are blocked. Landlock rules are additive — a rule can only
grant *more* access than its parents, never less — so "everything except this
file" has to be expressed by granting every sibling along the way instead. The
consequence is visible and worth knowing: **directories leading to a protected
path become create-restricted**. With `src/index.tsx` protected, everything in
`src/` and in the project root stays writable, but new files cannot be created
directly in either; new files inside `tests/`, `docs/` or any other subtree are
fine. `run --dry-run --backend landlock` lists exactly which directories are
affected.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | fine |
| 1 | a path is protected (`check`), or the plan cannot be enforced (`--dry-run`) |
| 2 | error: no policy, bad policy, no usable backend, command failed to start |

Otherwise `run` exits with your command's own status.

## Documentation

- [`architecture.md`](architecture.md) — how it is built and why the two
  backends work the way they do
- [`security.md`](security.md) — threat model, what is guaranteed, and the
  limitations that have been tested rather than assumed
- [`publishing.md`](publishing.md) — cutting a release: what a tag does, and
  how it reaches crates.io, npm and PyPI

## Development

```console
$ cargo test                    # policy, matching and CLI behaviour, any platform
$ cargo test --test enforcement # real bypass attempts, Linux only
```

The enforcement tests need a kernel that provides at least one backend. In a
container, `--security-opt seccomp=unconfined` is usually what makes user
namespaces available; Landlock needs 5.13+ with the LSM enabled.

## License

Copyright 2026 Ralon contributors.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE), or
<http://www.apache.org/licenses/LICENSE-2.0>.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this work is licensed under the same terms, per section 5 of the
license.
