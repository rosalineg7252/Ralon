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
$ cargo install ralon         # or from a checkout: cargo install --path .
$ npm install -g ralonlock    # prebuilt binary, wrapped
$ pip install ralonlock       # same binary
```

Or download a binary from the
[releases](https://github.com/stoneware-dev/Ralon/releases) — Linux builds are
static, so they run in any container.

The command is `ralon` however you install it. The policy file is called
`agent.lock`, not `ralon.lock`, on purpose: it is a format, not a product.
Anything could enforce it — this is one thing that does.

`run` enforces on **Linux** (mount namespaces, Landlock) and on **Windows**
(exclusive file handles). All three block *processes*, so they cover every
agent — including ones that have never heard of Ralon. **macOS** has no backend
yet; there `init`, `check`, `status` and `hook install` still work, and the
hook is a courtesy layer rather than enforcement. `ralon status` says which of
the two you are getting.

## Use

```console
$ ralon init                   # write a starter agent.lock, and wire up the agents
$ ralon status                 # what is protected, and what this machine can enforce
$ ralon check src/auth.ts      # is this path protected? exits 1 if it is
$ ralon check                  # list everything the policy protects right now
$ ralon run --dry-run -- npm test    # what would be locked, without locking it
$ ralon run -- claude          # the real thing
```

`ralon run` replaces itself with your command, so the agent keeps its
terminal, its exit code, and its signals. There is no supervisor process to kill
and nothing to keep running in the background.

### On Windows, start here

```console
$ ralon init                   # policy + hooks
$ notepad agent.lock           # say what must not change
$ ralon guard --detach         # done — every process is refused those paths
$ ralon guard --stop           # hand the files back when you want to edit them
```

A guard holds the locks with no command to supervise. Windows refuses those
locks to *every process*, so an agent started from an IDE, an extension,
another terminal, or installed next month is refused without knowing Ralon
exists — no `ralon run`, no configuration, nothing for the agent to opt into.
`ralon status` says whether one is running.

It refuses **writes to the paths you declared**, and nothing else. Reading is
untouched, so your build, tests, dev server, editor and `git` carry on
normally; everything outside the policy is untouched too. The only person it
gets in the way of is you, when you want to edit a protected file — which is
what `--stop` is for.

There is no way to refuse *only* an LLM agent and no one else. A process
carries no mark saying what it is, and agents write through `cmd`, `python`,
`node` and `git` — the same binaries you use. The hook below is the closest
thing, and it is defeatable for exactly that reason.

This works on Windows and not on Linux, for one reason worth understanding:
Windows enforcement is **held** by a process and applies to everyone else,
while Linux enforcement is **inherited** by a process before it runs. Inherited
is the stronger of the two — there is no supervisor to kill — but it cannot be
imposed on a process you did not start. On Linux, `ralon run` is the answer,
and `ralon guard` says so rather than pretending.

### The hook

`ralon init` installs this; `ralon hook install` does it on its own, and
`--no-hooks` skips it.

It writes a refusal into the configuration of **Claude Code**, **Cursor** and
**OpenCode**, so those agents are turned away before they edit a protected
path. `--agent` picks one. It works on every platform, including the ones where
`run` cannot enforce anything — which is exactly where it matters most.

For every other agent — Codex, Antigravity, GLM, Gemini, whatever ships next
month — use `ralon run`. It restricts the *process*, so it never needed to know
which agent it was running in the first place. Agents are only listed here
because a hook has to speak each one's configuration format, and only these
three document a hook that can refuse an edit before it happens.

Be clear about what it is worth. It covers the agent's **edit tools**; it does
not cover a shell command the agent runs, because a hook cannot tell which
paths `sed -i` will touch. On Linux the kernel catches those anyway. Elsewhere
they get through, which is why the hook is a courtesy and `run` is the
guarantee.

`ralon check` exits 1 for a protected path if you would rather wire it up
yourself, or gate a CI job on it.

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

- **Only what you launch** — unless a guard is running. A policy protects the
  processes started through `ralon run`; on Windows, `ralon guard` covers the
  rest of the machine as well, and on Linux an agent started some other way is
  not restricted.
- **Only what exists.** A protected path that is not on disk yet cannot be
  bind-mounted. `status` and `run` warn about patterns matching nothing. (Under
  the landlock backend such paths cannot be created at all, which is stricter.)
- **Not against root.** A process that can become root outside the namespace can
  undo anything. This defends against an agent doing something stupid or
  overreaching, not against an attacker with your password.
- **Not a secret store.** Protected files stay readable. `agent.lock` says what
  must not *change*; if a file must not be *read*, do not put it in the project.

## Backends

`run` picks the strongest backend the platform offers. `ralon status` shows
what is available, and `--backend mount|landlock|locks` pins the choice.

**locks** (Windows) — Ralon holds every protected file open allowing readers
and refusing writers, so writing, deleting, renaming or replacing one fails
with a sharing violation, for every process on the machine. ACLs would not do:
an agent runs as the same user, so any permission Ralon can set it can unset. A
handle is not a permission.

The one thing a handle cannot express is "and nothing may be added here", since
creating a file opens no existing object. That gap is covered by a deny ACE on
protected directories while Ralon runs — a narrowing rather than a guarantee,
because the agent owns the directory and an owner's `WRITE_DAC` cannot be
denied. It refuses every ordinary create; `security.md` is explicit about what
it does not refuse.

The protection lasts as long as Ralon does. A command started by `run` is tied
to a job object that dies with Ralon, so it cannot outlive the locks; a guard
has no child to tie, so killing one releases them.

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
