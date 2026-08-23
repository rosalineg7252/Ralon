# Security model

Agent Lock makes a narrow promise and tries to make it exactly. This document
says what the promise is, what it is not, and which of the claims have been
tested rather than reasoned about.

## Threat model

**Defends against:** a process that runs with your privileges, started by you
through `agent-lock run`, that tries to modify a path the policy protects. That
covers the ordinary case — an agent editing a file it should not have touched —
and the adversarial one: a prompt-injected agent that deliberately goes after
`.env`, an agent that shells out to `sed`, `python` or `git checkout`, and any
process it spawns, including ones that outlive it.

**Does not defend against:**

- **Root.** Anything that can become root outside the namespace can undo all of
  it. This is a guardrail for a tool you invited in, not a defence against an
  attacker who already has your password.
- **Processes you did not start this way.** The policy binds the process tree
  under `agent-lock run`. An agent launched directly is unrestricted, and so is
  a daemon that was already running — a language server, a file-watcher, an
  editor with a remote API. If a sandboxed process can ask one of those to write
  a file, the write happens outside the sandbox. Do not run an IPC-reachable
  writer alongside an agent you do not trust.
- **Reading.** Protected files stay readable, deliberately: `agent.lock`
  declares what must not *change*. A secret an agent must not read does not
  belong in the project directory.
- **Exfiltration.** Nothing here touches the network.
- **The kernel, the crates, the CPU.** A Landlock or namespace vulnerability, a
  compromised dependency, or hardware is out of scope.

## What is guaranteed

Inside `agent-lock run`, for every protected path, in that process and every
descendant:

| Attempt | Result |
| --- | --- |
| write, append, truncate, `cp` over it | denied |
| delete, rename away | denied |
| replace by renaming another file over it | denied |
| delete then recreate | denied |
| hard link or symlink over it | denied |
| create anything inside a protected directory | denied |
| rename or remove a directory on the way to it | denied |
| `chmod` then write | denied |
| reach the inode through a hard link made inside the sandbox | denied |
| escape by `umount`, `mount --bind`, or a nested namespace | denied |
| reach it through another process's `/proc/<pid>/root` | denied |
| read it | allowed |
| everything else in the project | unaffected |

Each row is a test in `tests/enforcement.rs`. They run a real shell inside a
real sandbox and then check the file from outside it, against every backend the
kernel offers.

## Why it cannot be undone

- A Landlock domain is one-way. There is no syscall to leave one, and it
  survives `fork` and `execve`.
- The mount namespace is locked before your command starts. Entering a second
  user namespace marks every inherited mount `MNT_LOCKED`, so `umount` fails and
  `copy_tree` refuses any bind mount that would expose what is underneath.
- `no_new_privs` is set, so a setuid binary cannot be used to climb out.
- Nothing supervises the sandbox, so there is nothing to kill. `agent-lock`
  *becomes* the command.

Two things fall out of the design rather than being enforced by a check:

**Hard links cannot reach a protected file.** Under the mount backend the
protected path is itself a mount point, and `link()` requires source and target
to be on the same mount — every attempt returns `EXDEV`. Under the Landlock
backend the same attempt is denied for a different reason: cross-directory links
need `REFER`, which the ancestor chain is never granted, and same-directory
links need `MakeReg` on a directory that is never granted either.

**`/proc/<pid>/root` is not a way out.** Following another process's root
requires `PTRACE_MODE_READ`, and a process in a nested user namespace does not
have it over processes in the parent one, even at the same uid. Verified: the
write returns `EPERM`.

## Known limitations

**A second path to the same directory bypasses both backends.** This is tested
and true: if the project is also visible at another mount point — a bind mount
made before the sandbox started, a volume mounted twice into a container, a
network share exported at two paths — writing through the other path is not
restricted. Both backends are path-based, and neither can protect a path it was
not told about. The sandboxed process cannot *create* such a mount (the mount
backend locks its namespace; the Landlock backend runs where user namespaces are
typically unavailable), so this requires the second path to already exist. If
your setup has one, protect it too or do not use it.

**Landlock alone can be defeated where user namespaces are available.** Landlock
rules apply to paths, not inodes. A process that can create its own mount
namespace can bind the project somewhere the carve-out granted, and write
through the new path. `auto` therefore prefers the mount backend, which is
available in exactly the environments where this attack is; forcing
`--backend landlock` on a machine with unprivileged user namespaces gives up a
real guarantee.

**Only paths that exist can be protected.** A bind mount needs something to
mount. `status` and `run` warn about patterns matching nothing. The Landlock
backend is stricter here by accident of its design: it forbids creating anything
in the ancestor directories, so a missing `.env` cannot be created at all.

**The policy is read before the sandbox starts.** Nothing races it — the scan
and the mounts happen in one single-threaded process before `exec` — but a path
created after that point is not protected for the lifetime of that run. Restart
the agent after adding files that need protecting.

**Landlock's create-restriction is a functional cost, not a security one.** See
`architecture.md`. It is why `mount` is the default.

## Verifying it yourself

```console
$ cargo test --test enforcement        # every attack, every available backend
$ agent-lock status                    # what this kernel can actually enforce
$ agent-lock run --dry-run -- claude   # exactly what will be locked
```

Do not take the tests' word for it either — check by hand:

```console
$ agent-lock run -- sh
$ echo x > .env            # EROFS or EACCES
$ rm .env                  # denied
$ echo x > src/App.tsx     # fine
```

If `status` reports no available backend, `run` refuses to start the command
rather than running it unprotected. A failure to enforce is never silent.

## Reporting a vulnerability

A bypass is anything that modifies a protected path from inside
`agent-lock run` without root, other than the limitations listed above. Please
report it privately — email the maintainers or open a GitHub security advisory —
with the policy, the command, and the kernel version (`uname -r`) and backend
(`agent-lock status`). A failing test case in the style of
`tests/enforcement.rs` is the most useful possible report.

## Hardening still on the table

- Warn when the project root is reachable through a second mount, by reading
  `/proc/self/mountinfo`.
- A seccomp filter denying `mount`, `umount2`, `unshare` and `setns` in the
  sandboxed process, as defence in depth behind the locked namespace.
- Applying both backends at once for callers who want the Landlock guarantees
  on top of the mount ones and can live with the create-restriction.
