//! What `chflags uchg` does and does not do, asserted rather than described.
//!
//! macOS only, and nobody working on this repository can run it — there is no
//! container for macOS. These exist so the macOS CI job is the thing that knows,
//! and so the claims in `security.md` and `enforce/macos/immutable.rs` are
//! checked against the kernel rather than against a memory of the BSD manual.
//!
//! Half of them assert a *weakness*. That is deliberate. This mechanism is a
//! narrowing an agent can undo, and the documentation says so; a test that
//! proves it can be undone is what stops the documentation drifting into a
//! stronger claim than the code supports. If `chflags nouchg` ever stops
//! working, that is a change to the threat model and should fail here first.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ralon");
const POLICY: &str = "version: 1\nprotect:\n  - .env\n  - config/**\n";

struct Project {
    root: PathBuf,
}

impl Project {
    fn new() -> Project {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        // Deliberately does not contain the name of the flag being tested for.
        // See `flagged` below for why that sentence had to be written down.
        let root = std::env::temp_dir().join(format!(
            "ralon-flags-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("config")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("agent.lock"), POLICY).unwrap();
        fs::write(root.join(".env"), "SECRET=original").unwrap();
        fs::write(root.join("config/db.yaml"), "original").unwrap();
        fs::write(root.join("src/App.tsx"), "original").unwrap();
        Project {
            root: fs::canonicalize(&root).unwrap(),
        }
    }

    fn ralon(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .arg("--dir")
            .arg(&self.root)
            .args(arguments)
            .current_dir(&self.root)
            .output()
            .expect("failed to run ralon")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn contents(&self, relative: &str) -> String {
        fs::read_to_string(self.path(relative)).unwrap_or_default()
    }

    /// A write from a shell Ralon never started.
    fn attack(&self, command: &str) {
        let _ = Command::new("sh")
            .args(["-c", command])
            .current_dir(&self.root)
            .output();
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        // Immutable files cannot be deleted, so the flags come off first or the
        // temp directory survives the test run.
        let _ = self.ralon(&["guard", "--stop"]);
        let _ = Command::new("chflags")
            .args(["-R", "nouchg"])
            .arg(&self.root)
            .output();
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Whether `path` carries `uchg`, asked of the filesystem rather than inferred
/// from a listing.
///
/// `stat -f %Sf` prints the flags and nothing else. The first version of this
/// ran `ls -ldO` and searched the whole line for `uchg` — and `ls` prints the
/// path it was given, which lived under a temporary directory this file used to
/// name `ralon-uchg-<pid>`. Every path "carried the flag", including the ones
/// asserted not to; three tests failed and the rest passed for no reason at all.
/// The lesson is the one in CLAUDE.md, one level up: check the property, not
/// something that mentions it.
fn flagged(path: &Path) -> bool {
    let flags = Command::new("stat")
        .args(["-f", "%Sf"])
        .arg(path)
        .output()
        .expect("failed to run stat");
    // Comma-separated when there is more than one, empty when there are none.
    String::from_utf8_lossy(&flags.stdout)
        .trim()
        .split(',')
        .any(|flag| flag == "uchg")
}

// ---------------------------------------------------------------------------
// What it does.
// ---------------------------------------------------------------------------

#[test]
fn a_guard_makes_the_protected_paths_immutable() {
    let project = Project::new();
    assert!(project.ralon(&["guard", "--detach"]).status.success());

    assert!(flagged(&project.path(".env")), ".env carries no flag");
    assert!(
        flagged(&project.path("agent.lock")),
        "the policy protects itself"
    );
    assert!(
        flagged(&project.path("config")),
        "the directory carries no flag"
    );
    assert!(
        flagged(&project.path("config/db.yaml")),
        "a file inside a protected directory carries no flag — the flag on the \
         directory only governs its entries, not their contents"
    );
    assert!(
        !flagged(&project.path("src/App.tsx")),
        "an unprotected file was flagged"
    );
}

#[test]
fn every_ordinary_write_is_refused() {
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);

    for attack in [
        "echo pwned > .env",
        "rm -f .env",
        "mv .env .env.bak",
        "cat src/App.tsx > .env",
        "sed -i '' 's/original/pwned/' .env",
        "printf x >> .env",
    ] {
        project.attack(attack);
        assert_eq!(
            project.contents(".env"),
            "SECRET=original",
            "`{attack}` got through"
        );
    }
}

#[test]
fn a_protected_directory_refuses_new_entries() {
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);

    project.attack("echo x > config/slipped-in.yaml");
    assert!(
        !project.path("config/slipped-in.yaml").exists(),
        "a new file was created inside a protected directory"
    );
    project.attack("echo x > src/allowed.tsx");
    assert!(
        project.path("src/allowed.tsx").exists(),
        "an unprotected directory stopped accepting files"
    );
}

#[test]
fn stopping_hands_everything_back() {
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);
    assert!(flagged(&project.path(".env")));

    assert!(project.ralon(&["guard", "--stop"]).status.success());

    assert!(!flagged(&project.path(".env")), "the flag was left behind");
    assert!(
        !flagged(&project.path("config")),
        "the flag was left behind"
    );
    project.attack("echo released > .env");
    assert_eq!(project.contents(".env").trim(), "released");
}

#[test]
fn starting_twice_is_the_same_as_starting_once() {
    let project = Project::new();
    assert!(project.ralon(&["guard", "--detach"]).status.success());
    assert!(
        project.ralon(&["guard", "--detach"]).status.success(),
        "a second start failed instead of being a no-op"
    );

    // And one stop is still enough to undo it.
    project.ralon(&["guard", "--stop"]);
    assert!(!flagged(&project.path(".env")));
}

#[test]
fn enforcement_outlives_the_process_that_applied_it() {
    // The property that makes a supervisor possible here at all: unlike the
    // Windows locks, nothing has to stay running. The flag is on the inode.
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);

    // `--detach` has already exited by the time this runs.
    assert!(flagged(&project.path(".env")));
    project.attack("echo pwned > .env");
    assert_eq!(project.contents(".env"), "SECRET=original");
}

// ---------------------------------------------------------------------------
// What it does not do. These document the limits and must keep passing.
// ---------------------------------------------------------------------------

#[test]
fn an_agent_can_undo_it_which_is_why_this_is_not_a_sandbox() {
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);
    assert_eq!(project.contents(".env"), "SECRET=original");

    // One command, no privileges, available to the agent. This is the whole
    // difference between `guard` and `run` on macOS, and `security.md` says so.
    // If this assertion ever fails, the mechanism got stronger and the docs are
    // now understating it — which is still a docs bug.
    project.attack("chflags nouchg .env && echo pwned > .env");
    assert_eq!(
        project.contents(".env").trim(),
        "pwned",
        "chflags nouchg no longer works — the threat model in security.md is out of date"
    );
}

#[test]
fn a_protected_directory_cannot_itself_be_renamed() {
    // Stronger than `immutable.rs` claimed, and worth pinning down. A protected
    // *directory* carries the flag in its own right, and an immutable directory
    // cannot be renamed or removed — so the gap below does not apply to it. The
    // first version of this file assumed otherwise and asserted that `mv config
    // config-moved` succeeded; the macOS job disagreed, and it was right.
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);

    project.attack("mv config config-moved");
    assert!(
        !project.path("config-moved").exists(),
        "a protected directory was renamed"
    );
    assert!(
        project.path("config").is_dir(),
        "a protected directory went missing"
    );
}

#[test]
fn renaming_an_unprotected_ancestor_moves_the_path_out_from_under_the_policy() {
    // The real gap, documented in `immutable.rs`: ancestors that are not
    // themselves protected are not pinned, because pinning them would stop the
    // project ever having a new file written anywhere inside. The contents stay
    // immutable; the path the policy named stops referring to them.
    //
    // `src/deep/` is the ancestor here — the policy names only the file inside
    // it, so nothing flags the directory.
    let project = Project::new();
    fs::create_dir_all(project.path("src/deep")).unwrap();
    fs::write(project.path("src/deep/secret.txt"), "original").unwrap();
    fs::write(
        project.path("agent.lock"),
        "version: 1\nprotect:\n  - src/deep/secret.txt\n",
    )
    .unwrap();
    project.ralon(&["guard", "--detach"]);
    assert!(flagged(&project.path("src/deep/secret.txt")));
    assert!(
        !flagged(&project.path("src/deep")),
        "the ancestor was flagged, so this test is no longer about the gap it names"
    );

    project.attack("mv src/deep src/moved");
    assert!(
        project.path("src/moved").exists(),
        "the ancestor rename was refused — if ancestors are pinned now, \
         immutable.rs is out of date"
    );

    // The contents are still protected, which is the half that holds.
    project.attack("echo pwned > src/moved/secret.txt");
    assert_eq!(project.contents("src/moved/secret.txt"), "original");
}

#[test]
fn a_path_that_cannot_be_flagged_is_reported_and_never_silently_skipped() {
    let project = Project::new();
    // A policy naming a path that is not on disk. Nothing can be flagged for it,
    // so the developer is told — otherwise `--detach` prints "every process on
    // this machine is now refused those paths" over a list that quietly has one
    // fewer path in it than the policy does.
    fs::write(
        project.path("agent.lock"),
        "version: 1\nprotect:\n  - .env\n  - missing.txt\n",
    )
    .unwrap();

    let started = project.ralon(&["guard", "--detach"]);
    let said = String::from_utf8_lossy(&started.stderr);
    // A pattern that matches nothing is a warning, not a silent success.
    assert!(
        said.contains("matches nothing on disk") || said.contains("not protected"),
        "an unenforceable entry was accepted without a word: {said}"
    );
    // And the rest of the policy is still enforced.
    assert!(flagged(&project.path(".env")));
}

#[test]
fn a_guard_that_was_killed_leaves_the_flags_on_which_is_the_safe_direction() {
    let project = Project::new();
    project.ralon(&["guard", "--detach"]);

    // Nothing to kill — `--detach` already exited — which is exactly the point:
    // the failure mode here is state left behind, not protection lost. `status`
    // has to report it so it is not a mystery.
    let status = project.ralon(&["status"]);
    let said = String::from_utf8_lossy(&status.stdout);
    assert!(said.contains("guard      running"), "{said}");
}
