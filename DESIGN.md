# Design

How Ralon works, end to end, on all three platforms — and why each piece is the
way it is. `architecture.md` goes deeper on the two Linux backends;
`security.md` states what is and is not guaranteed. This is the document to
read first.

---

## 1. The one idea

A developer writes a file saying what must not change. Something makes that
true.

```
.gitignore  →  what Git must not track
agent.lock  →  what AI-controlled processes must not modify
```

The file is called `agent.lock`, not `ralon.lock`, because it is a *format*.
Ralon is one program that enforces it; another program should be able to
enforce the same file. Naming the format after the tool would quietly make the
tool the point.

---

## 2. The pipeline

Everything up to `Plan` is ordinary, portable, unit-tested code. Only the last
step touches a syscall, and only that step is per-platform.

```
                       agent.lock
                            │
      policy.rs             │  parse + validate, find the project root
                            ▼
      Policy { root, version, patterns }
                            │
      matcher.rs            │  patterns → globset
                            ▼
      Matcher
                            │
      scan.rs               │  walk the project, prune protected directories
                            ▼
      [ProtectedPath { relative, absolute, is_dir, pattern }]
                            │
                            ├──────────────► check / status / hook — print and stop
                            │
      enforce/mod.rs        │  canonicalize, resolve a backend, build a Plan
                            ▼
      Plan { backend, protected, pinned, carve, profile }
                            │
                            ├── carve.rs      Landlock rules      (pure)
                            ├── profile.rs    Seatbelt SBPL text  (pure)
                            │
      enforce/<platform>/   │  the syscalls — the only unsafe code
                            ▼
              restrict, then run
```

**Why the split matters.** `--dry-run` produces the same plan on a machine that
cannot enforce it. A Windows laptop can print the exact Seatbelt profile a Mac
would be given, and a Linux CI runner can check the Landlock carve-out for a
tree it will never sandbox. What can be tested everywhere is tested everywhere;
what cannot is isolated into one small file per platform.

### The data

| Type | Holds | Built by |
| --- | --- | --- |
| `Policy` | root, version, declared patterns | `policy.rs` |
| `Matcher` | compiled globs | `matcher.rs` |
| `ProtectedPath` | one resolved path + the pattern that matched it | `scan.rs` |
| `Plan` | backend + everything that backend needs | `enforce/mod.rs` |
| `Backend` | `Mount \| Landlock \| Seatbelt \| Locks \| Immutable` | `resolve()` |

`Plan.pinned` is the ancestor directories of every protected path, parents
first. Three of the five backends populate it for one shared reason given in §4;
`landlock` gets the same protection out of its carve-out instead, and
`immutable` is left empty on purpose — §4 again, and it is the sharpest
limitation in this document.

---

## 3. Three process models

This is the part worth understanding before anything else, because it explains
an asymmetry that otherwise reads like an oversight.

### `ralon run` — inherited (Linux, macOS, Windows)

```
  ralon run -- claude
        │
        │  1. read policy, build plan
        │  2. restrict THIS process
        │  3. execve("claude")          ← ralon ceases to exist
        ▼
     claude                    restricted
        ├── sh -c 'sed -i ...' restricted   (inherited)
        └── python             restricted   (inherited)
                └── git        restricted   (inherited, and outlives them all)
```

The restriction is applied *before* the command starts and is inherited by
every descendant. There is no supervisor process left alive, so there is
nothing to kill, and no syscall exists to leave the restriction.

On Windows there is no inheritable restriction to hand over, so `run` keeps
holding the locks and supervises the child — the one place the model differs.
An agent could kill its supervisor, so the child is placed in a job object that
dies with Ralon: killing Ralon kills the command with it.

### `ralon guard` — imposed (Windows, macOS)

```
  ralon guard --detach
        │
        └── ralon (background)   holds handles to every protected path
                                            │
                                            │  refuses every other process
                                            ▼
   claude        VS Code        cmd.exe        a script from anywhere
   (blocked)     (blocked)      (blocked)      (blocked)
```

Nothing was wrapped. Nothing opted in. A Windows share-mode lock is refused to
*every process on the machine*, so an agent started from an IDE, an extension,
another terminal, or installed next month is refused without ever having heard
of Ralon.

macOS reaches the same place by a different route and arrives weaker. There is
nothing to hold: `chflags uchg` is a bit on the inode, so the "guard" is a state
on disk rather than a process, and it outlives the command that set it — a
reboot included. It is also a *narrowing*, undone by `chflags nouchg` with no
privileges at all. Both facts are stated wherever the backend appears, because
the shape of the diagram above is identical and the guarantee underneath it is
not.

### `ralon install` — a supervisor over `guard`

The third model, and the one most people use. It introduces **no new way to stop
a write**: a per-user background process notices `agent.lock` and starts exactly
the enforcement `guard` would have started, so nothing about it is easier to
bypass than `guard` is. What it adds is lifecycle, not mechanism.

```
  agent.lock appears  ──►  supervisor  ──►  guard for that project
  agent.lock removed  ──►  supervisor  ──►  released, state cleaned up
```

It therefore exists exactly where `guard` does. See §5.6.

### Why not all three, everywhere

| | inherited | imposed |
| --- | --- | --- |
| covers processes you started | yes | yes |
| covers processes you did **not** start | no | **yes** |
| survives being killed | nothing to kill | Windows: no · macOS: yes |
| needs privileges | no | no |

Linux restrictions are *applied to a process before it runs*. There is no
unprivileged interface for imposing one on a process you did not start —
`chattr +i` needs `CAP_LINUX_IMMUTABLE`, fanotify permission events need
`CAP_SYS_ADMIN`. Asking for root to protect a file from an agent hands the agent
a root process to talk to.

macOS has both: Seatbelt is inherited and cannot be imposed, `chflags` is imposed
and cannot be inherited. `run` takes the first, `guard` takes the second, and
`Backend::Auto` never returns the second so `run` cannot silently downgrade.

Windows locks are the mirror image of Linux: they cover everything, and they last
exactly as long as the process holding them.

So `guard` and the supervisor exist only where they can work, and `ralon install`
says why where they cannot rather than registering a service with nothing to do.

---

## 4. Ancestor pinning

Every path-based mechanism shares one weakness: a rule names a *path*, and
renaming a parent directory moves the file out from under the rule.

```
   protect: src/index.tsx        mv src src-moved

   before                        after
   src/index.tsx   ← protected   src-moved/index.tsx   ← nothing matches this
```

This was a real bypass, found by a test, not by reasoning. The fix is the same
idea everywhere it is possible, and each mechanism expresses it differently —
with one that cannot express it at all:

| Backend | How a directory is pinned |
| --- | --- |
| mount | bind the directory onto itself; the kernel refuses to rename a mount point |
| locks | hold a directory handle open with no share-delete |
| seatbelt | `(deny file-write-unlink (literal "/proj/src"))` — that path, that operation |
| landlock | falls out of the carve-out; ancestors are never granted `REFER` |
| immutable | **it cannot** — see below |

Both halves of the Seatbelt row are load-bearing. `subpath` instead of
`literal` would make the entire project read-only. And `file-write*` instead of
`file-write-unlink` would too, *if* Seatbelt consults the parent directory when
creating a child — which is exactly the kind of thing that cannot be checked
from a Windows laptop. Renaming and removing a directory are both an unlink of
that path, so the narrow rule closes the attack and cannot over-reach; the
broad one only works if an assumption holds.

### The one backend that cannot pin

Notice what the other four rows have in common: each expresses *"this directory
may not be renamed"* **without** also saying *"this directory may not accept new
entries"*. A mount point, a held handle, an unlink-only deny rule and an
ungranted `REFER` are all narrow enough to leave creation alone.

`chflags uchg` is not. One flag means both. So pinning `src/` would stop the
project ever gaining a file in `src/`, and pinning the project root — which every
policy needs, because `agent.lock` lives there — would stop it gaining a file
anywhere. `Plan::build` therefore returns no pinned directories for
`Backend::Immutable`, deliberately, and what that leaves open is a substitution:

```
   protect: src/deep/secret.txt         src/ and src/deep/ are not protected

   $ mv src/deep src/moved              allowed
   $ mkdir -p src/deep
   $ echo whatever > src/deep/secret.txt

   src/moved/secret.txt   original bytes, still immutable, read by nothing
   src/deep/secret.txt    the attacker's file, at the path the policy declared
```

The original bytes surviving is not the point. What every build, test run and
deploy opens is the declared path, and that now holds someone else's content.

This is a boundary rather than a bug, and the difference is that it is checked
rather than asserted. The whole family — rename an ancestor, rename a
grandparent, move it out of the tree, delete and rebuild it, swap it for a decoy,
symlink or junction over it — is run against every backend in
`tests/enforcement.rs` and `tests/supervisor.rs`, asserting on **the content at
the protected path** rather than on whether the rename failed, so a regression in
pinning cannot pass by refusing the first step alone. All of them hold on mount,
landlock, locks and seatbelt. `tests/immutable.rs` pins the exposed case from
both sides: that the substitution works today, and that it stops when the
*directory* is protected instead of the file inside it.

That last part is the mitigation, and `audit.rs` prints it — naming the file, the
unprotected ancestor, and the change that closes it — before the guard starts,
and again from `ralon status`. A protected directory carries the flag itself and
cannot be renamed, so the attack has nowhere to begin.

---

## 5. Platform mechanisms

### 5.1 Linux — `mount` (preferred)

`enforce/linux/mount.rs`. Read-only bind mounts in a private, locked namespace.

```
1.  unshare(CLONE_NEWUSER | CLONE_NEWNS)   own user + mount namespace
2.  write uid_map/gid_map                   keep our own identity, not `nobody`
3.  mount("/", MS_REC | MS_PRIVATE)         nothing leaks into the host tree
4.  for each pinned dir:   bind(dir, dir)   parents first — a later bind of a
                                            parent would hide the mounts under it
5.  for each protected:    bind + remount read-only
                                            (mount_setattr with AT_RECURSIVE,
                                             falling back to MS_REMOUNT|MS_RDONLY
                                             before Linux 5.12)
6.  chdir(cwd)                              re-resolve the working directory
                                            against the NEW tree
7.  unshare(CLONE_NEWUSER | CLONE_NEWNS)    again — this marks every inherited
                                            mount MNT_LOCKED
8.  execve(command)
```

Steps 6 and 7 are the two that are easy to get wrong and were both bugs first.

**Step 6:** the working directory handle still pointed into the pre-mount tree,
so relative lookups walked straight past everything just mounted — protection
silently did nothing while reporting success.

**Step 7:** entering a *second* user namespace locks the inherited mounts. The
kernel then refuses `umount` and refuses any bind mount that would reveal what
is underneath. Without it, the sandboxed process could simply unmount its way
out.

*Protects:* exactly the named paths. Nothing else in the project behaves
differently. *Needs:* unprivileged user namespaces, which some hardened distros
and container runtimes disable.

### 5.2 Linux — `landlock`

`enforce/linux/landlock.rs`, planned by `enforce/carve.rs`.

Landlock rules are **additive**: a rule can only grant *more* access than its
parents, never less. There is no way to say "everything except this file". So
the policy has to be turned inside out:

```
   protect: /proj/src/index.tsx

   walk / → /proj → /proj/src, and at each level grant every sibling
   EXCEPT the one on the path to the protected file:

   /            grant  /bin /etc /home /usr /var …      (not /proj)
   /proj        grant  README.md package.json tests/    (not src)
   /proj/src    grant  App.tsx utils.ts                 (not index.tsx)
```

`index.tsx` is never granted write access, so it has none.

The cost is visible and worth knowing: **directories on the way to a protected
path accept no new entries**, because "create here" cannot be granted without
also granting "write to the protected file here". `run --dry-run --backend
landlock` lists exactly which directories are affected. This is why `auto`
prefers `mount`.

ABI **V3** is pinned deliberately: it is the last ABI whose write set means
exactly "modify a file". V5 adds device ioctls and V9 adds unix socket
connects, neither of which a filesystem policy should be deciding.
`CompatLevel::BestEffort` degrades on older kernels rather than failing.

`carve.rs` takes its directory lister as a parameter, so the whole algorithm is
unit-tested against a fake tree on every platform.

### 5.3 macOS — `seatbelt`

`enforce/macos/seatbelt.rs`, planned by `enforce/profile.rs`.

macOS is the only platform whose sandbox can state the policy directly, because
SBPL has `deny`:

```lisp
(version 1)

; Everything not named below behaves normally.
(allow default)

; Declared in agent.lock.
(deny file-write*
    (literal "/proj/.env")
    (subpath "/proj/config"))

; The directories leading to them — unlink only, so they cannot be
; renamed or removed while everything inside them stays writable.
(deny file-write-unlink
    (literal "/proj")
    (literal "/proj/src"))
```

`sandbox_init(profile, 0, &error)` applies it to the calling process; it is
inherited across `exec` and cannot be left. Same shape as Linux — restrict,
then become the command.

Two consequences, both improvements on the platforms either side:

- No carve-out, so no create-restriction (unlike Landlock).
- A protected **directory** is a `subpath`, which covers entries created inside
  it *later* — the one thing a Windows handle cannot do.

`sandbox_init` has been deprecated since 10.8 and has no public header. It is
also what every sandboxed application on macOS uses, and the supported
alternative — the App Sandbox — is an entitlement on a signed `.app` bundle,
which a command-line tool cannot be. So it is a dependency on a deprecated API,
named in `security.md` rather than left implied. A profile the kernel rejects
is an error; the command is not started.

### 5.4 Windows — `locks`

`enforce/windows/`, four files, because Windows needs four mechanisms to do
what one does elsewhere.

**`locks.rs` — the guarantee.** Every protected file is held open with
`FILE_SHARE_READ`: readers allowed, writers refused. Windows arbitrates two
opens of the same file by the share mode the first one asked for, so every
attempt to write, delete, rename or replace it fails with a sharing violation —
for every process, whoever started it.

```
   ralon ──open(".env", GENERIC_READ, share=READ)──► handle held
                                                          │
   agent ──open(".env", GENERIC_WRITE, …)────────────► SHARING VIOLATION
   agent ──open(".env", DELETE, …)───────────────────► SHARING VIOLATION
   agent ──open(".env", GENERIC_READ, …)─────────────► fine
```

Directories are opened with `FILE_FLAG_BACKUP_SEMANTICS`; a protected directory
gets a handle *and* a handle on every file inside it.

**Not ACLs, and this was tested.** The agent runs as the same user, so any
permission Ralon can set it can unset. Even the version that looks like it
should work — an explicit deny ACE on `WRITE_DAC` itself — was removed by the
owner, who then wrote the file. An owner's `WRITE_DAC` is implicit and cannot
be denied. A handle is not a permission and cannot be argued with.

**`acl.rs` — the one gap, narrowed.** Creating a *new* entry inside a protected
directory opens no existing object, so no share mode is ever consulted and no
handle can refuse it. That is covered by a deny ACE for `Everyone` over
`FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY`, which refuses create, `mkdir`, copy
in, move in, and rename inside.

It is labelled a **narrowing, not a guarantee**, everywhere it appears, for the
reason above: an agent that rewrites the ACL gets its write. It refuses every
*ordinary* create and leaves only a route someone has to take deliberately.

The ACL is rebuilt ACE by ACE rather than through `SetEntriesInAcl`, because
`SetEntriesInAcl(REVOKE_ACCESS)` returned `ERROR_SUCCESS` and left the ACE
exactly where it was — the undo silently did nothing. A directory whose ACL
already names `Everyone` is left alone and reported.

**`job.rs` — closing the kill-the-supervisor hole.** `run` supervises rather
than `exec`s, so the child is put in a job object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Kill Ralon and the command dies with it,
so it cannot outlive the locks.

**`guard.rs` — the same locks, with nothing to supervise.** Guards rendezvous
through a named kernel event (`Local\ralon-guard-<hash of root>`): creating it
claims the project, waiting on it parks, signalling it asks for a clean
release. An object in the kernel rather than a pid file, so a guard that dies
takes its claim with it and leaves nothing stale.

`--detach` uses `CreateProcess` directly with `bInheritHandles = FALSE`.
`std::process::Command` must pass `TRUE` to hand over stdio, and the background
guard would then inherit the *shell's* pipe and hold it open for the rest of
the day — `ralon guard --detach | anything` would never finish. Observed, not
theorised.

---

### 5.5 macOS — `immutable`

`chflags uchg` on every protected path, and on every file inside a protected
directory. The only mechanism on macOS that can be *imposed* on a process nobody
started, which is the whole reason it exists: `guard` and the supervisor need
one, and this is the entire list. Endpoint Security is the other candidate and
wants an Apple-granted entitlement, root, and Full Disk Access — a privileged
process for an agent to talk to, which is worse than the problem.

**This reverses an earlier decision.** `enforce/unguarded.rs` used to cover macOS
and said this mechanism "is not implemented rather than being implemented and
described as protection". The objection was to the description and it was right,
so the description is the part that got the work:

- It is a **narrowing, not a boundary**. `chflags nouchg` undoes it, needs no
  privileges, and is available to the agent.
- It is **not process-level sandboxing** and is not equivalent to `ralon run`,
  which applies a profile the agent cannot drop, see, or ask the kernel to lift.
- It **cannot pin ancestors** — §4.

What it does buy is not nothing, and is verified on a real kernel rather than
described: every ordinary write fails. Editors, `>` redirects, `rm`, `mv`,
`sed -i`, `cat >`, and every agent's edit tool, for every process on the machine.

Two properties are the inverse of the Windows backend and worth holding in mind
together. The state is on the inode, so it **survives the process that set it** —
including a reboot, which is what lets the supervisor come back up and find its
work already done. And a Ralon that is killed **leaves the flags on**, which
fails *closed*: `status` reports the leftover and `guard --stop` clears it.

### 5.6 The supervisor

`ralon install` registers a per-user background process with the operating system
— a Task Scheduler logon task, a launchd LaunchAgent. Both are per-user by
construction, which is why none of it needs administrator or root.

It runs the lifecycle of §5.4 and §5.5 and adds no enforcement of its own. Three
parts, and the split is the design:

1. **Discovery** — a kernel watcher (`ReadDirectoryChangesW`, FSEvents) over the
   declared scopes, with a full sweep behind it on a deadline. The watcher makes
   it immediate; the sweep makes it *correct*, because a watcher reports changes
   and has nothing to say about state that existed before it started — after a
   reboot, that is every workspace on the machine.
2. **Decision** — `reconcile(known, on_disk, live, …)`, pure and tested on every
   platform. Three inputs, not two: what was recorded, what has a policy file,
   and what the kernel says is *actually* enforced. The third is why a reboot is
   survivable on Windows, where enforcement dies with the machine while
   `workspaces.json` still says `enforced`.
3. **Action** — `enforce::guard::{detach, stop, running, clear_leftovers}`.

**Scopes** are the directories a policy is honoured in, kept disjoint and
canonical. They are the answer to "why doesn't an `agent.lock` inside a
downloaded archive lock my files", and they are deliberately not tied to where
Ralon is installed — a home directory on `C:` says nothing about a repository on
`D:`. Even inside a scope the blast radius is bounded by the policy format:
patterns are relative and `..`, absolute paths and `~` are rejected, so the most
a hostile policy achieves by being found is making its own directory read-only.

---

## 6. Capability matrix

What each backend actually does, with no rounding up.

| | Linux `mount` | Linux `landlock` | macOS `seatbelt` | macOS `immutable` | Windows `locks` |
| --- | --- | --- | --- | --- | --- |
| write / append / truncate | denied | denied | denied | denied | denied |
| delete / rename away | denied | denied | denied | denied | denied |
| replace by rename | denied | denied | denied | denied | denied |
| create inside a protected dir | denied | denied | denied | denied | narrowed (ACL) |
| rename a **protected** directory | denied | denied | denied | denied | denied |
| rename an **unprotected** ancestor | denied | denied | denied | **bypass** | denied |
| read a protected file | allowed | allowed | allowed | allowed | allowed |
| other files in the project | untouched | **create-restricted ancestors** | untouched | untouched | untouched |
| used by `run` | yes | yes | yes | **never** | yes |
| covers processes it did not start | no | no | no | **yes** | **yes** |
| survives killing Ralon | nothing to kill | nothing to kill | nothing to kill | **yes** (fails closed) | no |
| the agent can undo it unprivileged | no | no | no | **yes** (`chflags nouchg`) | no |
| pre-existing hard link to the file | **bypass** | **bypass** | **bypass** | **bypass** | n/a |
| second mount of the project | **bypass** | **bypass** | — | — | — |

Every row marked **bypass** is reported by `audit.rs` before the agent starts:
they cannot be fixed by enforcing harder, so the only honest response is to say
so while there is still time to change the policy.

Read the `immutable` column as a whole rather than row by row. It is the weakest
of the five and it is the only one available where it is used, which is why
`run` never selects it and why every document that mentions it says both things
in the same breath.

---

## 7. The hook layer

Enforcement covers processes. Hooks cover the window before enforcement is
running — and they are a *courtesy*, said in those words everywhere they
appear, because an agent that shells out has left their reach and an agent that
can edit the project can delete them.

There is a second reason they matter, which is not about stopping anything.
Ralon owns the wording of exactly one refusal, and this is it. Everywhere else
the message is made by whatever attempted the write, out of an error code Ralon
caused but does not control: Node renders a Windows sharing violation as
`EBUSY: resource busy or locked`, which reads like a corrupt file rather than a
policy. Observed in a real session — the agent retried, renamed around it,
shelled out, and worked out what was happening only by reading `agent.lock`
itself. With the hook installed it is told it is protected by Ralon, which file,
and which pattern matched. So the supervisor installs hooks into each project as
it enforces it, and `--no-hooks` opts out.

Nine agents document a hook that can refuse an edit before it happens. They
disagree about everything: the file, the event name, the request shape, and the
word for "no".

**The matcher is shared, and built from verbs.** Several agents scope their hook
with a regex over the tool name, and each file used to carry its own hand-written
list of that agent's tools. Four files, four chances to miss a spelling, and the
failure is silent every time — which duly happened: Claude Code's list read
`Write|Edit|MultiEdit|NotebookEdit`, an agent called a tool its own transcript
displayed as `Update`, and the hook never ran.

`hook::write_matcher` now generates one alternation from verbs, matching either
case with `[Ww]rite`-style classes because that is the one construct every
agent's regex engine agrees on. It is deliberately *not* over-broad: the matcher
decides the **message**, not the **protection** — a write it never sees is still
refused by the kernel — so every verb in the list is one a real agent tool
contains, and speculative ones were removed after they matched a great many MCP
tools that touch no file and cost a process on every call. `bash`, `shell`, `run`
and `exec` remain absent: a hook cannot tell which paths an arbitrary command
will touch, and a matcher that pretended otherwise would be false confidence.

```
                 stdin: the agent's request, in its own shape
                                    │
                                    ▼
                        ralon hook check
                                    │
            ┌───────────────────────┴───────────────────────┐
            │  targets()   every path key, at any depth,    │
            │              compared case- and underscore-   │
            │              insensitively                    │
            │  only_reads() a read is always allowed        │
            │  Matcher      is it protected?                │
            └───────────────────────┬───────────────────────┘
                                    ▼
              ONE json document + exit code 2

  { "hookSpecificOutput": { "permissionDecision": "deny", … },  ← Claude, Copilot, Codex
    "decision": "deny", "reason": …,                             ← Gemini, Antigravity
    "permission": "deny", "agent_message": …,                    ← Cursor
    "cancel": true, "errorMessage": …,                           ← Cline
  }                                     exit 2                   ← OpenCode, Windsurf
```

Emitting a key an agent ignores costs nothing. Omitting one it needs is an edit
waved through. So the refusal is said in every dialect at once, and there is
one `hook check` rather than nine.

Two design points that are easy to miss:

**Reads are never refused.** Some agents call the hook for *every* tool, not
only for edits. Without a read check, an agent would be refused permission to
look at the very policy governing it. A tool name that is not recognisably a
read is treated as a write, because the two mistakes are not equal: refusing a
read is an annoyance the user sees at once; allowing a write is the failure
this program exists to prevent.

**Some agents are deliberately not installed.** JetBrains Junie ignores
project-local hooks by default, so the file would silently do nothing. Roo Code
has no hook API yet, and its `.rooignore` blocks reads as well as writes.
Shipping configuration that does nothing is worse than shipping none.

---

## 8. Failure policy

Three rules. Each exists because the alternative produces a tool that *looks*
like it is working.

**If nothing can enforce, refuse to start.** `run` does not launch the command
unprotected. "Unavailable" on its own leaves the reader free to conclude the
policy is protecting them, so the message says plainly that nothing is, and
what to do instead.

**Report what enforcement cannot fix, before the agent starts.** `audit.rs`:
a hard link to a protected file, a second mount of the project, a file another
program already holds open. Afterwards there is nothing to be done about them.

**Leftover state fails closed.** If Ralon is killed before removing the Windows
deny ACE, the ACE stays — refusing writes to a directory the policy protects
anyway. `status` reports it; `guard --stop` clears it.

---

## 9. How this is tested

Enforcement claims are verified by attempting real bypasses and then reading
the filesystem — **never** by checking an exit code.

That rule was earned, three times, and the third is the general form of the
other two.

`del` returns 0 when it failed, `>` returns 0 when it was refused, and
`SetEntriesInAcl` returned `ERROR_SUCCESS` while changing nothing. This project's
own attack script once printed "create inside a protected directory: HELD"
without ever looking to see whether the file had appeared. It had.

Then twice more, in checks that looked at the *wrong thing* rather than at an
exit code. The Windows attack helper passed a quoted path to `cmd` through
`Command::arg`, which escapes `"` as `\"` — a spelling `cmd` does not parse — so
the redirect never ran, the file was unchanged, and every enforcement assertion
would have passed against a Ralon that enforced nothing. And `flagged()` searched
`ls -ldO` output for `uchg` while the temporary directory was named
`ralon-uchg-<pid>`; `ls` prints the path it was given, so every path carried the
flag.

The rule those produce, now in CLAUDE.md: **check the property, not something
that mentions it — and prove the control case**, that the write succeeds before
the policy applies.

| Where | What runs | Verified by |
| --- | --- | --- |
| any machine | policy, matcher, scan, carve, profile, hook, `reconcile`, scopes | `cargo test` |
| Linux | `tests/enforcement.rs` — the attack tables, every backend | Docker, CI |
| macOS | the same attack tables against Seatbelt, plus `tests/immutable.rs` | CI only — no container exists |
| Windows + macOS | `tests/supervisor.rs` — install → policy → enforced, and the ancestor family | `cargo test` |
| Windows | `tests/cli.rs` — locks, the directory gap, the guard | `cargo test` |

`RALON_REQUIRE_BACKEND=1` turns "no backend available, nothing was tested" into
a failure, so a CI job cannot pass by silently skipping.

Nobody working on this repo can run the macOS backend locally. Three things
compensate, and none of them is optimism:

- The reviewable part is reviewable everywhere — the profile generator and
  `reconcile` are platform-independent and unit-tested, and
  `--dry-run --backend seatbelt` prints the profile on any machine.
- `cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings`
  needs no Apple SDK, so the macOS code and its tests are type-checked from
  Windows or Linux before they are pushed. It has already caught `chflags` typed
  as `c_ulong`, which compiles everywhere except the platform it runs on.
- `tests/immutable.rs` deliberately asserts **weaknesses** as well as guarantees:
  that `chflags nouchg` still undoes the flag, and that the ancestor substitution
  in §4 still works. If either ever fails, the mechanism got stronger and this
  document is overstating the gap — which is a bug too, and that is where it
  surfaces.

Release safety is part of this. `release.yml` calls `ci.yml` as a reusable
workflow before it builds anything, because a tag push does not fire the
`push`/`pull_request` events and a release previously ran no tests at all. The
publish step is gated behind a manual approval, which is only a gate if the
`release` environment has a required reviewer configured — a repository setting
no workflow file can enforce, so it is stated in the workflow.

---

## 10. Extension points

**A new platform** is a new directory under `enforce/` exposing two functions:

```rust
pub fn availability() -> Vec<(Backend, Availability)>;
pub fn enforce_and_exec(plan: &Plan, command: &[OsString]) -> Result<ExitCode>;
```

Plus, if it can hold a policy open without supervising a command, a `guard`
module exposing `AVAILABLE`, `BACKEND` and the session functions; otherwise it
inherits `enforce/unguarded.rs`, which explains why not. Put the *planning* in a
platform-independent file, as `carve.rs` and `profile.rs` do.

**A supervisor comes free with a `guard`.** `supervisor/` contains no platform
code: it drives `enforce::guard`, so a platform that gains a guard gains
automatic enforcement by adding a `service/` file that registers a per-user
background process. A platform that cannot guard must not get a service —
see `service/unsupported.rs` for why a green `active (running)` over nothing is
worse than a refusal.

**A new agent** is one new file in `hook/` with its settings path, its event
name and its entry. Use `hook::write_matcher` rather than listing that agent's
tool names; §7 is what happens otherwise. If it refuses in a dialect nothing else
speaks, add that key to `Decision::render` — it is one document for all of them.

**A new bypass** is a failing test in `tests/enforcement.rs` first. The attack
tables are one line per attack and run against every available backend. Assert on
the state the attack was trying to reach — the content at the protected path —
not on whether the first step of it failed.

**A weakness that cannot be fixed** is a finding in `audit.rs`, a row in the §6
matrix, and an entry in `security.md`. If a developer can change their policy to
close it, the finding must say how: a warning nobody can act on teaches people to
ignore warnings.

---

## 11. Rejected designs

**ACLs on Windows.** See §5.4 — same user, so any permission Ralon sets the
agent can unset. Tested, not assumed.

**A daemon that watches and reverts.** Works everywhere, needs no kernel
interfaces. It is also a race — the write lands, and something may read the
file before the revert — and it means a tool that protects your data by
deleting data. A guarantee that is usually true is what this program exists not
to ship.

This is worth separating from §5.6, since both involve a background process and
only one of them is rejected. The supervisor never watches a *protected file* and
never reverts anything. It watches for `agent.lock`, and what it does about it is
start the same kernel enforcement a person would have started by hand. If the
supervisor is killed, the enforcement it started stays exactly as strong; if a
watch-and-revert daemon is killed, there is nothing left at all. The rejected
design puts the daemon *in* the guarantee. This one puts it in the lifecycle.

**Blocking agents by identity.** There is no way to refuse "an LLM agent" and
nobody else. A process carries no mark saying what it is, and agents write
through `cmd`, `python`, `node` and `git` — the same binaries you use. The
closest honest thing is the hook layer, which is defeatable for exactly that
reason.

**A restricted token on Windows** (a SID the protected files do not grant, so
the refusal applies to the agent's process tree and not to you) is the one
rejected design that is *technically* right — it is how Chromium sandboxes
renderers. It is a large piece of work with real breakage risk, since the agent
then needs that SID granted on everything else it legitimately touches. Noted
as the path to true agent-only enforcement, not started.

---

## 12. What is deliberately absent

No GUI. No password. No account. No cloud service. No human approval workflow.
No dependency on any particular agent. Each would add a component that can be
down, be phished, or need a subscription — to a tool whose entire job is to
make one sentence true about a filesystem.
