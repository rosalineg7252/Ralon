# ralon

`agent.lock` declares what AI agents may not modify. Ralon makes the kernel
agree.

```yaml
# agent.lock — commit it, it is per-repository policy
protect:
  - src/auth.ts
  - .env
  - config/**
```

```console
$ npm install -g ralonlock       # the command it installs is `ralon`
$ pip install ralonlock          # the same binary, delivered as a wheel
```

(This page is the documentation for both packages. `npm` and PyPI both refused
the name `ralon`; the command is `ralon` either way.)

## Install once → declare policy → enforcement starts automatically

On **Windows and macOS**, set the machine up one time and never run a command in
a repository again:

```console
$ ralon install                  # registers a per-user background supervisor
$ ralon scope add D:\Projects    # …and say where your code actually lives
```

Or, for a single repository and nothing else on the machine:

```console
$ cd my-project && ralon install --here
```

After that, any repository under a scope that contains an `agent.lock` is
enforced within a second — including ones cloned next month. Delete the file and
enforcement stops.

`install` uses your home directory as a first-run default and then tells you
which drives it does *not* cover, because where Ralon is installed says nothing
about where you keep repositories:

```console
No scope covers D:\ — an agent.lock there is not enforced.
If that is where you keep code:
  ralon scope add D:\Projects
```

Day to day:

```console
$ ralon status                   # is this project protected, and by what
$ ralon scope list               # every scope, and what is enforced in each
$ ralon pause                    # release this project to edit its own policy
$ ralon resume
$ ralon uninstall                # stop, and hand every project back
```

`ralon pause` exists because `agent.lock` protects itself — which is the point of
it, and does mean you cannot rewrite your own policy while it is enforced. A
pause expires on its own unless you pass `--indefinitely`.

## Per-command enforcement

On **Linux** there is no supervisor, and the reason is worth knowing rather than
working around: every Linux mechanism is *inherited* by a process before it runs
and cannot be imposed on one already running. `ralon install` says so instead of
registering a service that would come up green and enforce nothing. There you
wrap the agent, which is stronger anyway — the restriction becomes part of the
process and there is nothing left to kill:

```console
$ ralon run -- claude            # the agent, and every process it spawns
$ ralon run --dry-run -- npm test
$ ralon check src/auth.ts        # exits 1 if the path is protected
$ ralon check                    # list everything the policy protects
```

Without installing anything: `npx ralonlock check src/auth.ts`, or
`pipx run ralonlock check src/auth.ts`.

## What the guarantee is

For every protected path: write, append, truncate, delete, rename away, replace
by rename, and creating files inside a protected directory are all **denied**.
Reading is untouched, and everything outside the policy is untouched.

It binds **processes, not agents** — the blocked process does not have to know
what Ralon is — so it covers every agent equally, including ones with no hook
support at all.

| Platform | Supervisor | `ralon run` |
| --- | --- | --- |
| Windows | ✅ exclusive file handles | ✅ same mechanism |
| macOS | ⚠️ `chflags uchg` — a narrowing an agent can undo, **not** a sandbox | ✅ Seatbelt, cannot be dropped |
| Linux | ❌ not possible; `install` explains why | ✅ mount namespaces or Landlock |

Where a project is enforced, Ralon also configures the agent's own hook, so an
agent that reaches a protected path is told **"protected by Ralon"**, which file,
and which pattern matched — rather than being handed `EBUSY: resource busy or
locked` and left to conclude the repository is broken. `--no-hooks` turns that
off; enforcement does not depend on it.

## Removing it

Run `ralon uninstall` **before** removing the package.

```console
$ ralon uninstall                # deregister, release every project
$ npm uninstall -g ralonlock     # or: pip uninstall ralonlock
```

`ralon install` registers a background process with the operating system, and no
package manager knows about that. None of them can do it for you either: npm
stopped running `preuninstall` scripts, and `pip` and `cargo` never had an
uninstall hook. So this is a step you take, on every platform. Skip it and the
supervisor stays registered and keeps enforcing after the command used to stop it
is gone.

The supervisor runs from its own copy of the binary in Ralon's state directory,
so a package manager's files are never held open and removing the package always
works. If you removed the package first, the copy is still there and still a
working `ralon` — `ralon status` will tell you where.

## About this package

It ships prebuilt binaries and installs only the one matching your platform —
Linux (x64, arm64), macOS (Intel, Apple silicon) and Windows (x64).

The npm package puts a small Node shim in front of each invocation, which passes
through exit codes and signals unchanged; the wheel installs the binary directly
as a console script, with nothing in front of it. For a long-running agent
neither matters. `cargo install ralon` and the
[release binaries](https://github.com/stoneware-dev/Ralon/releases) are the same
program without a package manager in the way.

Exit codes are the interface and are never swallowed: `0` fine, `1` a path is
protected (`check`) or the plan cannot be enforced (`--dry-run`), `2` an error.
Otherwise `run` exits with your command's own status.

Full documentation, the threat model, and the limitations that were tested rather
than assumed: <https://github.com/stoneware-dev/Ralon>

Apache-2.0.
