# Architecture

The whole-system design, all three platforms, is in `DESIGN.md` — read that
first. This document goes deeper on the two Linux backends, which are the
oldest and the most intricate.

```
agent.lock
    │  policy.rs      parse + validate (serde_yaml_ng)
    ▼
Policy { root, version, patterns }
    │  matcher.rs     patterns → globs
    ▼
Matcher
    │  scan.rs        walk the project, prune protected directories
    ▼
[ProtectedPath]  ──────────────────► check / status print this and stop
    │  enforce/mod.rs canonicalize, pick a backend, build a Plan
    ▼
Plan { backend, protected, pinned, carve, profile }
    │  enforce/linux/  (or macos/, windows/)
    ▼
restrict this process ──► execve(command)
    │
    ▼
the agent, and every process it will ever spawn
```

Nothing runs after `execve`. There is no daemon, no wrapper process, no fd
passed to the child. The restriction lives in the kernel, attached to the
process, inherited by everything it forks. (Windows is the exception in both
respects: it has no inheritable restriction, so `run` supervises, and `guard`
is a process that deliberately stays alive. See `DESIGN.md` §3.)

## Modules

| File | Responsibility |
| --- | --- |
| `main.rs` | dispatch, exit codes |
| `cli.rs` | clap definitions only |
| `commands.rs` | one function per subcommand, all printing |
| `policy.rs` | parse and validate `agent.lock`, find the project root |
| `matcher.rs` | patterns → `globset`, path matching |
| `scan.rs` | resolve patterns against the filesystem |
| `audit.rs` | conditions that weaken a policy without breaking it |
| `hook/` | one file per agent, plus the shared decision |
| `enforce/mod.rs` | backend selection, `Plan`, ancestor pinning |
| `enforce/carve.rs` | Landlock rule planning (pure, filesystem injected) |
| `enforce/profile.rs` | Seatbelt profile text (pure, tested everywhere) |
| `enforce/linux/` | `mount.rs`, `landlock.rs`, `sys.rs` |
| `enforce/macos/` | `seatbelt.rs`, `immutable.rs`, `guard.rs` |
| `enforce/windows/` | `locks.rs`, `acl.rs`, `job.rs`, `guard.rs` |
| `enforce/unguarded.rs` | why a guard cannot work on this platform |
| `supervisor/mod.rs` | `reconcile` (pure), and the daemon loop around it |
| `supervisor/registry.rs` | scan roots, remembered workspaces, the sweep |
| `supervisor/single.rs` | one supervisor per user, claimed with a handle |
| `supervisor/watch/` | `windows.rs`, `macos.rs`, `sweep.rs` |
| `service/` | `windows.rs` (Task Scheduler), `macos.rs` (launchd), `unsupported.rs` |

The platform directories hold all the `unsafe` code and are the only files that
do not compile everywhere. Everything else builds and is tested on all three
platforms, which is what keeps `check`, `status` and `hook install` usable in
mixed teams and in CI — and what lets `--dry-run` show the same plan on a
machine that cannot enforce it.

## The supervisor

`ralon install` → a repository with an `agent.lock` is enforced, with nothing run
inside it. Three pieces, and the split between them is the design:

1. **Discovery** — a kernel watcher (`ReadDirectoryChangesW`, FSEvents) over the
   scan roots, with a full sweep behind it on a 60-second timer and at start-up.
   The watcher is the mechanism and the sweep is the correctness boundary: a
   watcher reports *changes*, so it has nothing to say about the state that
   already existed when it started — after a reboot, that is every workspace on
   the machine. A watcher that fails to start degrades to the sweep and says so.
2. **Decision** — `reconcile(known, on_disk, live, now, retry_failed)`, pure and
   tested on every platform including the ones with no supervisor. Three inputs,
   not two: what was recorded, what has a policy file, and what is *actually*
   enforced according to the kernel. The third is what makes a reboot recoverable
   — on Windows the record says `enforced` after a restart and nothing is.
3. **Action** — `enforce::guard::{detach, stop, running, clear_leftovers}`. The
   supervisor contains no platform code and no enforcement of its own; it starts
   the same guard a person would. Idempotence comes free from the guard's claim
   being a kernel object rather than a file.

The asymmetry between platforms lands entirely in `enforce/*/guard.rs`. Windows
spawns a detached guard process per workspace, so one crash does not unprotect
the others and a surviving guard is adopted rather than duplicated. macOS applies
`chflags uchg` directly, because the state is on the inode and there is nothing
to hold. Linux has no `guard`, so `ralon install` refuses — `service/unsupported.rs`
explains at length why a systemd unit would be worse than nothing.

Workspace identity is the **canonical** path. This is load-bearing: the Windows
guard's claim is a hash of the project path, so two spellings of one directory
are two projects that cannot see each other, and the supervisor would decide a
guard was not running while it was. It is canonicalized once, where the path
enters the system, and un-prefixed only for display.

### Scopes

A scope is a directory Ralon will honour an `agent.lock` inside. The set is kept
**disjoint** by `Config::add`: a path already inside a scope is reported as
covered rather than added, and a path containing existing scopes absorbs them.
That is not tidiness — overlapping scopes mean the sweep walking a subtree twice
and two filesystem registrations reporting the same events, and it is the
difference between "you already have this" and a configuration a person has to
diff by eye.

Scopes are canonicalized when added, which is what lets `covers()` be a plain
component-wise `starts_with`: both sides have already been resolved, so casing,
`.`, and junctions cannot produce two scopes that fail to recognise each other's
repositories. Component-wise also means `D:\Projects` does not swallow
`D:\Projects-old`.

Removing a scope needs no release logic of its own. Drop it from the
configuration and reconcile: the sweep no longer returns those workspaces, so
`reconcile` already emits `End` for each. Adding one is the mirror image.

Two things the running supervisor has to notice, both learned the hard way:

- **The scope set can change underneath it.** `ralon scope add` writes the
  configuration from another process, so the state directory is registered
  alongside the scopes and a write to `config.yaml` is what wakes the daemon.
  Without that a new drive waited for the sweep — and appeared to work only
  because the state directory happened to sit under the one scope being watched.
- **Most filesystem events are noise.** A registration is recursive and
  unfiltered, so a scope on a home directory reports every write under `AppData`.
  Only `agent.lock` and `config.yaml` can change what should be enforced;
  everything else is ignored, and the sweep runs on a deadline rather than a
  timeout so that constant activity cannot starve it.

## Policy semantics

Patterns are relative to the directory holding `agent.lock`, which is also the
project root. Discovery walks up from the working directory, like `git`.

Each pattern becomes up to two globs: `config` matches `config` *and*
`config/**`, so a directory pattern protects the directory itself as well as its
contents — otherwise the directory could simply be renamed. `*` does not cross
`/` (`literal_separator`), `**` does. Matching is case-insensitive on Windows
and macOS, because on a case-insensitive filesystem a deny list that matched
fewer paths than the filesystem does would be wrong in the dangerous direction.

`agent.lock` is always pattern zero. A policy an agent can rewrite is not a
policy.

Rejected at parse time rather than reinterpreted: `..` anywhere, absolute paths,
`~`, `!` negation, unknown keys, unknown versions. A policy that does not mean
what it says is worse than no policy.

Scanning prunes: when a directory matches, it is recorded once and not descended
into. Protecting `node_modules` costs one entry, not two hundred thousand.

## The mount backend

The default. Sequence, all in the `ralon` process before `exec`:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` — a user namespace grants the
   privileges needed to mount; a mount namespace keeps the mounts out of the
   host. `uid_map`/`gid_map` map the current ids onto themselves, so the agent
   keeps the identity it was started with instead of becoming `nobody`.
2. `mount(MS_REC | MS_PRIVATE, "/")` — nothing propagates back to the host.
3. **Pin the ancestors.** Every directory between the project root and a
   protected path is bind-mounted onto itself, read-write. The access rights do
   not change; the point is that it becomes a *mount point*, and the kernel
   refuses to rename or remove one. Without this, `mv src src-moved` succeeds:
   the read-only mount follows the directory, the file keeps its contents, and
   the path the policy named is gone.
4. **Bind the protected paths read-only.** `mount_setattr(AT_RECURSIVE)` on
   Linux 5.12+, so submounts are covered too; otherwise a classic
   `MS_REMOUNT | MS_BIND | MS_RDONLY`, repeating the flags a user namespace
   refuses to let a remount clear (`nosuid`, `nodev`, `noexec`, atime).
5. **Re-enter the working directory.** `cwd` is a `(mount, dentry)` pair
   resolved before any of this, so relative lookups through it would walk
   straight past every new mount. `chdir` to the same path resolves it against
   the new tree. This was a real bug: pinning the project root silently disabled
   all protection until the `chdir` was added.
6. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` again. Mounts inherited from a more
   privileged namespace are `MNT_LOCKED`: they cannot be unmounted, and
   `copy_tree` refuses any bind mount that would reveal what is under them. This
   is what makes step 4 permanent.

Order matters twice: parents before children (a bind mount of a directory does
not carry the mounts already inside it), and the locking `unshare` last.

## The landlock backend

Landlock rules are **additive**. A rule on a subdirectory can only grant *more*
access than its parents, never less; there is no way to write "everything is
writable except this file". This single fact determines the whole design.

So the carve-out: walk from `/` down to each protected path, and grant full
write access to everything that branches off the way. The ancestor chain itself
is granted nothing.

```
protect: src/index.tsx

/                     no grant   ← create-restricted
├── usr               GRANT
├── tmp               GRANT
└── home/dev/proj     no grant   ← create-restricted
    ├── package.json  GRANT
    ├── tests/        GRANT      (whole subtree, new files included)
    └── src           no grant   ← create-restricted
        ├── App.tsx   GRANT
        └── index.tsx (nothing)  ← protected
```

Only write rights are handled (`AccessFs::from_write`), so reads are never
checked and never denied. ABI v3 is requested with `CompatLevel::BestEffort`:
v3 is the last ABI whose write set means exactly "modify a file" — v5 adds
device ioctls, v9 unix socket connects — and best-effort silently drops what an
older kernel does not have.

The visible cost: **directories on the ancestor chain accept no new entries**,
because granting "create a file here" requires granting `WriteFile` on the
hierarchy, which would make the protected file writable. `run --dry-run
--backend landlock` lists exactly which directories are affected, and
`tests/enforcement.rs::only_landlock_blocks_new_files_beside_a_protected_one`
pins the behaviour so it cannot regress silently.

`carve::plan` takes the directory lister as an argument, so the algorithm is
unit-tested against a fake tree on every platform, with no filesystem involved.

## Backend selection

`auto` prefers `mount`: it protects exactly what the policy names and leaves
everything else alone. It falls back to `landlock`, which needs no namespaces
and therefore works in the container runtimes and hardened distros that disable
unprivileged user namespaces — which is, conveniently, where the mount backend
cannot run.

Availability is probed honestly. Landlock: `landlock_create_ruleset(NULL, 0,
LANDLOCK_CREATE_RULESET_VERSION)` returns the ABI version. Mount: `fork` a child
that attempts the `unshare` and report its errno, because nothing short of
trying it is trustworthy. Both are reported by `ralon status`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | fine |
| 1 | a path is protected (`check`), or the plan cannot be enforced (`--dry-run`) |
| 2 | error: no policy, bad policy, no usable backend, command failed to start |

Anything else comes from the command itself, unchanged, because `run` becomes
that command.

## Testing

`cargo test` — policy parsing, pattern matching, carve planning, and the CLI
end to end, on any platform.

`cargo test --test enforcement` — Linux only. Creates a real project, runs a
real shell inside a real sandbox, attempts the attack, and then inspects the
file *from outside the sandbox*. Every test runs against every backend the
kernel provides, so a backend cannot pass by being unavailable. Attacks live in
one table; adding a case is one line.

In a container: `--security-opt seccomp=unconfined` is usually what makes user
namespaces available, so both backends get exercised.

## Adding a backend

1. Add a variant to `Backend` and to `availability()`.
2. Add whatever planning it needs to `Plan::build` (keep it pure and testable,
   like `carve.rs`).
3. Apply it in `enforce_and_exec` before the `exec`.
4. Add it to the list in `tests/enforcement.rs::usable_backends`. The existing
   attack tables then run against it unchanged.
