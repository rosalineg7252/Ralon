# Releasing Ralon

`ralon` is on crates.io. `0.1.0` was published by hand from a dirty working
tree, so it corresponds to no commit; everything from `0.1.1` on is built and
published by CI from a tag. crates.io has `0.1.1`; npm and PyPI start at
`0.1.2`, because the registry configuration for those two was only fixed in
that release. The versions converge from there.

## What a tag does

```
git tag v0.1.1
      │
      ▼
    guard ......... the tag must match Cargo.toml, or nothing is built
      │
┌─────┴─────┬───────────┬───────────┬───────────┐
▼           ▼           ▼           ▼           ▼
linux-x64  linux-arm64  macos-arm  macos-x64  windows-x64
└───────────┴─────┬─────┴───────────┴───────────┘
                  ▼
         GitHub release + binaries
                  │
                approve ....... one manual gate; all three are permanent
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
 crates.io       npm           PyPI
ralon crate  ralon + five   ralonlock
             @stoneware-dev  wheels
```

The command is `ralon` from all three. Only the PyPI *project* is called
`ralonlock`, because `ralon` was not available there.

`.github/workflows/release.yml` does all of it. npm and PyPI ship the *same*
binaries the workflow built — not a second compile — so what someone installs
with `npm i ralon` is byte-identical to the archive on the release page.

The `approve` gate is deliberately manual. Every one of these registries is
effectively append-only, so a mistaken tag is not something to discover
afterwards.

## One-time setup

Until these exist the publish jobs fail; the binaries still build.

**GitHub → Settings → Environments → `release`**, with a required reviewer.
That is the gate above.

**crates.io** → API Tokens → new token, scope *publish-update*, restricted to
the `ralon` crate → repository secret `CARGO_REGISTRY_TOKEN`.

**npm** — two different kinds of package, which is the thing to get right:

- the five platform packages are **scoped**, `@stoneware-dev/<platform>`, and
  owned by the org of that name;
- the package users install, `ralon`, is **unscoped**. Unscoped names live in
  npm's global namespace and belong to a *user account*, not to any org.

```console
$ npm login
$ npm org create stoneware-dev          # free for public packages
```

The token must therefore cover both. A granular token limited to the
`@stoneware-dev` scope publishes the five and then fails on `ralon` — with a
404, because npm will not admit that a package you cannot write to exists. Give
it read+write on **all packages**, or publish `ralon` once by hand and then add
it to the token by name. Save it as the repository secret `NPM_TOKEN`.

**PyPI** — the project is **`ralonlock`**, not `ralon`. Publishing → add a
trusted publisher: project `ralonlock`, owner `stoneware-dev`, repository
`Ralon`, workflow `release.yml`, environment blank. Nothing to store; PyPI
verifies the workflow over OIDC. For a project that does not exist yet, use the
pending-publisher form.

## Cutting a release

```console
# 1. version — Cargo.toml is the single source of truth for all three registries
$ vim Cargo.toml                       # version = "0.1.2"
$ cargo build                          # refreshes Cargo.lock
$ vim CHANGELOG.md                     # what changed; Security section if relevant

# 2. prove it still enforces — Windows and macOS cannot tell you this
$ cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
$ docker run --rm --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    -v "$PWD:/work" -w /work -e CARGO_TARGET_DIR=/tmp/target \
    -e RALON_REQUIRE_BACKEND=1 rust:1-bookworm cargo test
$ cargo publish --dry-run

# 3. commit, push, wait for CI
$ git commit -am "Release v0.1.2" && git push

# 4. tag: builds the binaries, then waits for you
$ git tag -a v0.1.2 -m "v0.1.2" && git push --tags

# 5. check the release page, verify a checksum, then approve the run in Actions
```

The Docker line is not optional. `cargo test` on macOS or Windows never touches
an enforcement backend, so it cannot tell you whether the thing this project
exists to do still works. `RALON_REQUIRE_BACKEND=1` turns "no backend
available, nothing tested" from a pass into a failure.

Check `security.md` still describes reality before every release. Its
limitations section is the honest part of the pitch and it ages faster than the
code.

## Trying the packaging without releasing

Both packagers run locally against any binary:

```console
$ cargo build --release
$ mkdir -p artifacts/x86_64-unknown-linux-musl
$ cp target/release/ralon artifacts/x86_64-unknown-linux-musl/

$ node packaging/build-npm.mjs --version 0.1.2 --binaries artifacts --out dist --allow-missing
$ python packaging/build-wheels.py --version 0.1.2 --binaries artifacts --out dist --allow-missing

$ (cd dist/ralon && npm pack --dry-run)   # what npm would upload
$ twine check dist/*.whl                  # what PyPI validates on upload
```

`--allow-missing` is what makes a single-platform trial possible. The release
workflow never passes it: a package whose optionalDependencies were never
published is broken on install, for everyone.

## How the wrappers work

**npm** (`npm/`, assembled by `packaging/build-npm.mjs`) — five packages each
holding one binary and declaring `os`/`cpu`, so npm downloads only the matching
one, plus the `ralon` package listing them as `optionalDependencies` whose
`bin/ralon.js` execs whichever was installed. The shim passes the exit code
straight through: ralon's codes are its interface (1 = a path is protected,
2 = error), and a hook that swallowed them would report every policy as
satisfied. It costs a Node process per invocation, which is why the README
points at `cargo install` first.

**PyPI** (`packaging/build-wheels.py`) — one wheel per platform, each carrying
the binary in `ralonlock-<version>.data/scripts/`, the directory pip installs
onto PATH with the executable bit set. Nothing is importable; the wheel is only
a delivery mechanism for `pip install` and `uv tool install`. The Linux wheels
declare a manylinux *and* a musllinux tag, which one static binary legitimately
satisfies. `PROJECT` at the top of the script is the only place the PyPI name
lives.

`packaging/targets.json` is the single place a Rust target maps to its npm and
wheel identifiers. Adding a platform means editing it and the workflow matrix,
nothing else.

## Versioning

While on `0.x`, the minor is the breaking position.

What counts as breaking is not only the CLI:

- **Policy semantics are the real API.** If a pattern that used to protect a
  path stops protecting it, that is breaking and security-relevant, however
  obscure the pattern.
- Bumping `version:` in `agent.lock` needs a major release and a migration note.
  Old files must keep working, or fail loudly — never be misread.
- Weakening a guarantee in `security.md`, or dropping a backend, is breaking.
- Matching *more* paths is not breaking, but say so: people's builds will start
  failing and they deserve to know why.

Keep `CHANGELOG.md` current, with a Security section per release. When a
release fixes a bypass, say what could be modified, in which versions, and
under which backend.

## Metadata that has to stay true

- `description` and `keywords` are the whole of discoverability. "ralon" means
  nothing to a searcher; "agent", "sandbox", "landlock" are what they type.
- `license = "Apache-2.0"` matches `LICENSE`, which holds the canonical text
  from apache.org verbatim. crates.io shows the SPDX field, not the file.
- No `NOTICE` file, deliberately: Apache-2.0 §4(d) only binds redistributors
  when one exists. Adding one puts it in every downstream distribution — keep
  it to attribution, not release notes.
- `rust-version = "1.79"` is a promise. CI pins stable, so either add a job on
  1.79 or raise the field when you use something newer.
- `exclude` keeps the release plumbing out of the crate tarball. Crate users
  get the tool and the documentation that explains its limits, not the npm
  wrapper.
- `repository` is frozen per published version. Move the repo again and it must
  reach `Cargo.toml` before the next publish, or that link is a redirect
  forever.

## Other ecosystems

Still open, if anyone asks:

| Target | How | Worth it when |
| --- | --- | --- |
| Homebrew, AUR, Nix | community formulas, built from a tagged release — never a branch | someone offers; not worth chasing |
| `.deb` | `cargo-deb`, one command | the audience is Linux developers, which it is |

One standing rule: **do not** ship a `curl \| sh` installer. A tool meant to
stop untrusted software from writing to your disk should not be installed by
piping the internet into a shell.

## When a publish job fails

The jobs are independent, so one registry failing does not roll back another.
Fix the configuration and use **Re-run failed jobs** on the same run: a re-run
reads the workflow from the tag, so anything that needs a *workflow* change
needs a new tag, but configuration changes do not.

**npm: `404 Not Found - PUT .../@stoneware-dev%2f<platform>`** — the scope does
not exist, or the token cannot write to it. npm answers 404 rather than 403 so
the endpoint cannot be used to probe for private packages, which makes it look
like the wrong error. Run `npm org create stoneware-dev` and give the token
read+write on `@stoneware-dev/*`. A token problem alone would be 401.

**npm: the five platform packages publish and `ralon` fails** — the token
covers the scope but not the unscoped name, as above. The platform packages are
already up, so the release only needs its last package; there is no reason to
burn a version:

```console
$ npm login
$ node packaging/build-npm.mjs --version 0.1.2 --meta-only --out dist
$ npm publish --access public dist/ralon
```

`--meta-only` builds just that package, listing every platform, without needing
the binaries to hand. Fix the token afterwards so the next release does not
stop in the same place.

**PyPI: `invalid-publisher: valid token, but no corresponding publisher`** —
the OIDC claims do not match the trusted publisher. The log prints the claims;
compare them field by field with the PyPI configuration. The usual culprit is
`environment`: the `pypi` job declares none, so the claim is `MISSING`, and a
publisher configured with an environment name will never match. Either leave
the publisher's environment blank, or add `environment:` to the job and name it
identically.

**crates.io: `crate version already exists`** — that version is spent. Bump and
tag again; do not try to work around it.

## Things that bite

- **Versions come from the tag**, everywhere. Never edit a version in
  `npm/package.json`; it is a template, stamped at build time.
- **Publish order matters on npm.** Platform packages first, then `ralon`. The
  workflow does this; by hand in the other order you publish a package nobody
  can install.
- **Everything is append-only.** crates.io: yank, never replace. npm: unpublish
  only within 72 hours, deprecate after. PyPI: a deleted version's number can
  never be reused.
- **The first run of anything new is the real test.** If npm or PyPI fails
  after crates.io succeeded, fix forward with a new version — the number is
  already spent.

## After a release

Two reports matter, and they need opposite responses:

- *"It blocked something it should not have"* — usually the Landlock
  create-restriction. Ask for `ralon run --dry-run` output; it lists exactly
  which directories stopped accepting new entries.
- *"It did not block something it should have"* — a bypass. Treat it as a
  security issue: reproduce it as a test in `tests/enforcement.rs` first, fix
  second, and say plainly in the changelog what was exposed and in which
  versions.
