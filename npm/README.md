# ralon

`agent.lock` declares what AI agents may not modify. Ralon makes the kernel
agree.

```console
$ npm install -g ralonlock       # the command it installs is `ralon`
$ ralon init                     # write a starter agent.lock
$ ralon check src/auth.ts        # is this path protected? exits 1 if it is
$ ralon run -- claude            # run an agent that cannot touch them
```

Without installing: `npx ralonlock check src/auth.ts`.

Inside `ralon run` — and in every process it spawns — the protected paths are
read-only to the kernel. Not a linter, not a hook the agent can talk its way
past. `open()` returns `EROFS`, `rm` returns `EACCES`.

```yaml
# agent.lock
version: 1

protect:
  - src/auth.ts
  - .env
  - config/**
```

This package ships prebuilt binaries and picks the right one for your platform.
`run` enforces on Linux; `init`, `check` and `status` work everywhere, which is
what CI and pre-commit hooks need.

Installing through npm adds a Node process in front of each invocation. For a
long-running agent that is irrelevant, but `cargo install ralon` or the
[release binaries](https://github.com/stoneware-dev/Ralon/releases) skip it.

Full documentation, the threat model and the tested limitations:
<https://github.com/stoneware-dev/Ralon>

Apache-2.0.
