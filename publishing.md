# Publishing

What has to happen before this is something other people can install, in order.

## 0. Blockers as things stand

- The project is **not a git repository** yet.
- `Cargo.toml` has a placeholder: `repository = "https://github.com/your-org/agent-lock"`.
- The crate publishes as **`agentlock`** (decided), because `agent-lock` is
  taken on crates.io by an unrelated crate. Not yet claimed — see step 2.
- No `CHANGELOG.md`, `CONTRIBUTING.md`, or code of conduct.

Everything below assumes those are being fixed as you go.

## 1. Repository

```console
$ git init
$ git add .
$ git commit -m "Agent Lock: agent.lock policies, enforced by the kernel"
$ gh repo create agentlock --public --source=. --push
```

`.gitignore` already excludes `/target`. CI (`.github/workflows/ci.yml`) runs
`fmt`, `clippy` and the tests on Linux, Windows and macOS; on Linux that
includes the real bypass tests. Turn on branch protection requiring it before
taking outside contributions — this is a tool whose whole value is that its
enforcement works.

## 2. Claim the name

The crate is **`agentlock`**. The binary stays **`agent-lock`**, set by
`[[bin]] name` in `Cargo.toml`, because that is the command people type and it
mirrors the `agent.lock` file it reads:

```console
$ cargo install agentlock      # installs the `agent-lock` binary
```

`agentlock` was unclaimed when this was written, but names get taken. Check
again immediately before the first publish — this is the one step that cannot
be undone afterwards:

```console
$ cargo info agentlock         # errors if it does not exist yet: good
```

Also be aware of the neighbours, and expect to be confused with them:
`agent-lock` (an unrelated concurrency lock) and `agent-locker` (an alpha
sandbox for coding agents). Worth a sentence in the README saying what this is
not.

## 3. Fix the metadata

In `Cargo.toml`, before the first publish:

- `repository`, and add `homepage` and `documentation` if they differ.
- Confirm `description`, `keywords` (max 5), `categories` (must be real
  crates.io categories: `command-line-utilities`, `development-tools` are).
- `license = "Apache-2.0"` matches `LICENSE`, which holds the canonical text
  from apache.org verbatim. Keep them in agreement — crates.io shows the SPDX
  field, not the file.
- Apache-2.0 brings a patent grant and a termination clause, which is why
  companies tend to accept it more readily than MIT for infrastructure. It also
  obliges redistributors to include the license and to note modified files, so
  keep `LICENSE` in the published tarball (`cargo package --list` should show
  it).
- No `NOTICE` file, deliberately: section 4(d) only binds redistributors when
  one exists, and there is nothing to attribute yet. If you add one, it becomes
  part of every downstream distribution — keep it to attribution, not release
  notes.
- `readme = "README.md"` is already set, so the crates.io page is the README.
- Consider `exclude = [".github/", "*.md"]` if you would rather not ship the
  docs in the crate tarball. I would ship them; they are small and the security
  model is not optional reading.
- `rust-version = "1.79"` is a promise. CI pins stable, so either add a job on
  1.79 or raise the field when you use something newer.

## 4. Pre-flight

```console
$ cargo fmt --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test                              # your platform
$ docker run --rm --security-opt seccomp=unconfined \
    -v "$PWD:/work" -w /work -e CARGO_TARGET_DIR=/tmp/target \
    rust:1-bookworm cargo test            # Linux, both backends, real attacks
$ cargo package --list                    # what actually ships
$ cargo publish --dry-run
```

The Docker line is not optional for a release. `cargo test` on macOS or Windows
never touches an enforcement backend, so it cannot tell you whether the thing
this project exists to do still works.

## 5. Publish

```console
$ cargo login                  # token from crates.io/settings/tokens
$ cargo publish
$ git tag -a v0.1.0 -m "v0.1.0" && git push --tags
```

crates.io is append-only: a published version can be yanked but never replaced.
Dry-run first, every time.

## 6. Binaries

Most users of a security tool would rather not compile it. A tag-triggered
workflow covers it:

```yaml
name: Release
on:
  push:
    tags: ["v*"]

jobs:
  binaries:
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest,  target: x86_64-unknown-linux-musl }
          - { os: ubuntu-latest,  target: aarch64-unknown-linux-musl }
          - { os: macos-latest,   target: aarch64-apple-darwin }
          - { os: windows-latest, target: x86_64-pc-windows-msvc }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: "${{ matrix.target }}" }
      - run: cargo build --release --target ${{ matrix.target }}
      - uses: softprops/action-gh-release@v2
        with:
          files: target/${{ matrix.target }}/release/agent-lock*
```

Prefer **musl** for the Linux artifacts: a static binary with no glibc version
to match, which matters for a tool people will drop into containers. Landlock
and the mount syscalls work the same there.

Ship macOS and Windows binaries too, clearly labelled: `run` will refuse on
them, but `check` and `status` are exactly what a mixed-platform team needs in
CI and in pre-commit hooks. `cargo-binstall` picks these up automatically if the
asset names follow the default pattern.

## 7. Versioning

While on `0.x`, treat the minor as the breaking position.

What counts as breaking is not only the CLI:

- **Policy semantics are the real API.** If a pattern that used to protect a
  path stops protecting it, that is a breaking change and a security-relevant
  one, no matter how obscure the pattern.
- Bumping `version:` in `agent.lock` needs a major release and a migration note.
  Old files must keep working, or fail loudly — never be misread.
- Weakening a guarantee in `security.md`, or dropping a backend, is breaking.
- New patterns matching *more* is not breaking, but say so in the changelog:
  people's builds will start failing and they deserve to know why.

Keep a `CHANGELOG.md` with a "Security" section per release. When a release
fixes a bypass, say what could be modified, in which versions, and under which
backend.

## 8. Beyond cargo

- **Nix / AUR / Homebrew** — community packaging is fine to accept, but the
  binary must come from a tagged release, not a branch.
- **Distro packages** — a `.deb` is the highest-value one, since the audience is
  Linux developers. `cargo-deb` gets there in one command.
- **Do not** ship a `curl | sh` installer for this. A tool that is supposed to
  stop untrusted software from writing to your disk should not be installed by
  piping the internet into a shell.

## 9. First-release checklist

- [ ] `git init`, first commit, repository pushed, CI green on all three OSes
- [ ] Crate name confirmed available, `Cargo.toml` metadata filled in
- [ ] Linux tests run in Docker with both backends exercised
- [ ] `README.md` install command matches the published crate name
- [ ] `security.md` limitations section is current — that is the honest part of
      the pitch, and it ages faster than the code
- [ ] `CHANGELOG.md` started
- [ ] `cargo publish --dry-run` clean
- [ ] Tag pushed, binaries attached, release notes point at `security.md`

## 10. After

Watch for the two failure reports that matter and answer them fast: "it blocked
something it should not have" (usually the Landlock create-restriction — check
`--dry-run` output with them), and "it did not block something it should have"
(a bypass; treat it as a security issue, reproduce it as a test in
`tests/enforcement.rs` before fixing).
