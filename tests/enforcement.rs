//! Real bypass attempts against a real sandbox.
//!
//! Every test here runs a shell inside `ralon run` and then checks the
//! filesystem from outside it — never an exit code, which lies in both
//! directions. Unix only: `run` on Windows is covered by `tests/cli.rs`,
//! because the attacks there are `cmd.exe` and the interesting cases (a guard,
//! a held-open file) have no counterpart here.
//!
//! The tables run against every backend the machine offers: `mount` and
//! `landlock` on Linux, `seatbelt` on macOS. A backend that behaves
//! differently says so in the one test that asks about the difference, rather
//! than by being excluded from the rest.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ralon");

const POLICY: &str = "\
version: 1

protect:
  - src/index.tsx
  - .env
  - config/**
";

const LOCKED_CONTENT: &str = "original\n";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ralon-enforce-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        // macOS hands out temp directories under `/var`, which is a symlink to
        // `/private/var`. Ralon canonicalises the paths it protects, so the
        // test works from the real path too — otherwise these tests would
        // quietly be about symlink resolution rather than about enforcement.
        let root = fs::canonicalize(&root).unwrap_or(root);
        let sandbox = Sandbox { root };

        sandbox.write("agent.lock", POLICY);
        sandbox.write(".env", LOCKED_CONTENT);
        sandbox.write("src/index.tsx", LOCKED_CONTENT);
        sandbox.write("config/db.yaml", LOCKED_CONTENT);
        sandbox.write("src/App.tsx", "writable\n");
        sandbox.write("tests/smoke.txt", "writable\n");
        sandbox
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }

    fn exists(&self, relative: &str) -> bool {
        self.root.join(relative).exists()
    }

    /// Runs `script` with `sh` inside the sandbox.
    fn attempt(&self, backend: &str, script: &str) -> Output {
        Command::new(BINARY)
            .args(["--dir"])
            .arg(&self.root)
            .args([
                "run",
                "--quiet",
                "--backend",
                backend,
                "--",
                "sh",
                "-c",
                script,
            ])
            .current_dir(&self.root)
            .output()
            .expect("failed to run ralon")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Backends this platform could offer at all. Whether it *does* is asked of
/// the tool below, never assumed here.
const CANDIDATES: &[&str] = if cfg!(target_os = "linux") {
    &["mount", "landlock"]
} else {
    &["seatbelt"]
};

/// Backends this kernel can actually provide, as reported by the tool itself.
fn usable_backends() -> Vec<&'static str> {
    let probe = Sandbox::new();
    CANDIDATES
        .iter()
        .copied()
        .filter(|backend| {
            Command::new(BINARY)
                .arg("--dir")
                .arg(&probe.root)
                .args(["run", "--backend", backend, "--dry-run", "--", "true"])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        })
        .collect()
}

/// Runs `test` against every backend this kernel provides.
///
/// A kernel that provides none cannot demonstrate anything, and a green tick
/// from one would be a lie. Where the kernel is under our control — the
/// `enforcement` CI job — `RALON_REQUIRE_BACKEND` makes that a failure.
/// Elsewhere (a laptop, a runner whose own sandbox forbids it) it says so and
/// stops.
fn for_each_backend(test: impl Fn(&str)) {
    let backends = usable_backends();
    if backends.is_empty() {
        assert!(
            std::env::var_os("RALON_REQUIRE_BACKEND").is_none(),
            "RALON_REQUIRE_BACKEND is set, but this kernel offers no enforcement \
             backend — run `ralon status` to see why"
        );
        eprintln!("no enforcement backend on this kernel: nothing was tested");
        return;
    }
    for backend in backends {
        eprintln!("--- backend: {backend}");
        test(backend);
    }
}

/// Every way a program might try to change a protected file.
const ATTACKS: &[(&str, &str)] = &[
    ("overwrite", "echo hacked > src/index.tsx"),
    ("append", "echo hacked >> src/index.tsx"),
    ("truncate", ": > src/index.tsx"),
    (
        "copy over",
        "echo hacked > /tmp/x && cp /tmp/x src/index.tsx",
    ),
    ("delete", "rm -f src/index.tsx"),
    ("rename away", "mv src/index.tsx src/moved.tsx"),
    (
        "replace by rename",
        "echo hacked > src/tmp.tsx && mv src/tmp.tsx src/index.tsx",
    ),
    (
        "replace by delete and create",
        "rm -f src/index.tsx; echo hacked > src/index.tsx",
    ),
    // `/etc/hosts` rather than anything distribution-specific: this table runs
    // on macOS too, and a source file that does not exist would turn a real
    // attack into a shell error that passes.
    ("hard link over", "ln -f /etc/hosts src/index.tsx"),
    ("symlink over", "ln -sf /etc/hosts src/index.tsx"),
    (
        "chmod then write",
        "chmod 777 src/index.tsx; echo hacked > src/index.tsx",
    ),
    ("rename the parent", "mv src src-moved"),
    // The ancestor family. Moving a directory on the way to a protected file is
    // only half an attack; the half that matters is what goes back in its place.
    // The file's bytes surviving under a new name is no comfort at all if the
    // path the policy named now holds someone else's content — that is what
    // every build, test run and deploy will read.
    //
    // Every backend here pins its ancestors, so all of these fail at the first
    // `mv`. They are written out in full anyway: the assertion is on the content
    // at the protected path, so if pinning ever regresses these fail rather than
    // the table quietly still passing on the rename alone.
    (
        "rename the parent, then substitute",
        "mv src src-moved; mkdir -p src; echo hacked > src/index.tsx",
    ),
    (
        "rename the grandparent, then substitute",
        "mkdir -p a/b && mv src a/b/ 2>/dev/null; mkdir -p src; echo hacked > src/index.tsx",
    ),
    (
        "swap the parent for a decoy",
        "mkdir -p decoy && echo hacked > decoy/index.tsx && mv src old && mv decoy src",
    ),
    (
        "symlink the parent at a decoy",
        "mkdir -p evil && echo hacked > evil/index.tsx && rm -rf src && ln -s evil src",
    ),
    (
        "delete the parent, then rebuild it",
        "rm -rf src; mkdir -p src; echo hacked > src/index.tsx",
    ),
];

#[test]
fn a_protected_file_survives_every_attack() {
    for_each_backend(|backend| {
        for (name, script) in ATTACKS {
            let sandbox = Sandbox::new();
            let output = sandbox.attempt(backend, script);

            assert_eq!(
                sandbox.read("src/index.tsx"),
                LOCKED_CONTENT,
                "{backend}/{name}: protected file changed\nstderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                sandbox.exists("src/index.tsx"),
                "{backend}/{name}: protected file disappeared"
            );
        }
    });
}

#[test]
fn a_protected_directory_cannot_be_written_to() {
    let scripts = [
        ("write inside", "echo hacked > config/db.yaml"),
        ("create inside", "echo hacked > config/new.yaml"),
        ("mkdir inside", "mkdir config/sub"),
        ("delete inside", "rm -f config/db.yaml"),
        ("remove the tree", "rm -rf config"),
        ("rename the tree", "mv config config-moved"),
    ];

    for_each_backend(|backend| {
        for (name, script) in scripts {
            let sandbox = Sandbox::new();
            let output = sandbox.attempt(backend, script);
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

            assert_eq!(
                sandbox.read("config/db.yaml"),
                LOCKED_CONTENT,
                "{backend}/{name}: protected file changed\nstderr: {stderr}"
            );
            assert!(
                !sandbox.exists("config/new.yaml") && !sandbox.exists("config/sub"),
                "{backend}/{name}: something was created inside a protected directory"
            );
            assert!(
                sandbox.exists("config"),
                "{backend}/{name}: the protected directory disappeared"
            );
        }
    });
}

#[test]
fn the_policy_file_cannot_be_rewritten() {
    for_each_backend(|backend| {
        let sandbox = Sandbox::new();
        sandbox.attempt(backend, "echo 'version: 1' > agent.lock; rm -f agent.lock");
        assert_eq!(
            sandbox.read("agent.lock"),
            POLICY,
            "{backend}: agent.lock is not protecting itself"
        );
    });
}

#[test]
fn unprotected_files_stay_writable() {
    for_each_backend(|backend| {
        let sandbox = Sandbox::new();

        let output = sandbox.attempt(
            backend,
            "echo changed > src/App.tsx && \
             echo new > tests/new.txt && \
             mkdir -p tests/deep && echo new > tests/deep/file.txt && \
             rm tests/smoke.txt",
        );

        assert!(
            output.status.success(),
            "{backend}: ordinary work was blocked\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(sandbox.read("src/App.tsx"), "changed\n");
        assert_eq!(sandbox.read("tests/deep/file.txt"), "new\n");
        assert!(!sandbox.exists("tests/smoke.txt"));
    });
}

/// The one place the backends behave differently, and the reason `mount` is
/// preferred: Landlock cannot grant "create here" without also granting "write
/// to the protected file here", so directories leading to a protected path stop
/// accepting new entries.
///
/// `mount` and `seatbelt` both express the policy exactly and leave the
/// directory alone. If this ever starts failing for `seatbelt`, the ancestor
/// rules have become subtrees and the whole project has quietly gone
/// read-only — which would look like nothing at all until someone tried to
/// work in it.
#[test]
fn only_landlock_blocks_new_files_beside_a_protected_one() {
    for_each_backend(|backend| {
        let sandbox = Sandbox::new();
        let output = sandbox.attempt(backend, "echo new > notes.md");

        match backend {
            "mount" | "seatbelt" => {
                assert!(
                    output.status.success(),
                    "{backend}: creating a file next to a protected one should work\nstderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(sandbox.read("notes.md"), "new\n");
            }
            "landlock" => {
                assert!(!output.status.success(), "landlock: expected this to fail");
                assert!(!sandbox.exists("notes.md"));
            }
            other => unreachable!("unknown backend {other}"),
        }
    });
}

#[test]
fn the_restriction_is_inherited_by_child_processes() {
    for_each_backend(|backend| {
        let sandbox = Sandbox::new();
        // Two levels of nesting, the second one detached from the shell.
        sandbox.attempt(
            backend,
            "sh -c 'sh -c \"echo hacked > src/index.tsx\"' ; \
             nohup sh -c 'echo hacked > .env' >/dev/null 2>&1; sleep 0.2",
        );

        assert_eq!(sandbox.read("src/index.tsx"), LOCKED_CONTENT);
        assert_eq!(sandbox.read(".env"), LOCKED_CONTENT);
    });
}

/// Escapes that only exist where mounts do.
#[test]
#[cfg(target_os = "linux")]
fn the_sandbox_cannot_be_unmounted_or_bound_around() {
    let escapes = [
        ("umount", "umount src/index.tsx; echo hacked > src/index.tsx"),
        (
            "bind around the parent",
            "mkdir -p /tmp/escape && mount --bind . /tmp/escape && echo hacked > /tmp/escape/src/index.tsx",
        ),
        (
            "remount read-write",
            "mount -o remount,rw src/index.tsx; echo hacked > src/index.tsx",
        ),
        (
            "new namespace",
            "unshare -Umr sh -c 'echo hacked > src/index.tsx'",
        ),
    ];

    if !usable_backends().contains(&"mount") {
        eprintln!("mount backend unavailable, skipping");
        return;
    }

    for (name, script) in escapes {
        let sandbox = Sandbox::new();
        let output = sandbox.attempt("mount", script);
        assert_eq!(
            sandbox.read("src/index.tsx"),
            LOCKED_CONTENT,
            "escaped via {name}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn a_nonexistent_protected_path_is_reported_not_silently_ignored() {
    let sandbox = Sandbox::new();
    fs::remove_file(sandbox.root.join(".env")).unwrap();

    let output = Command::new(BINARY)
        .arg("--dir")
        .arg(&sandbox.root)
        .args(["run", "--dry-run", "--", "true"])
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("read-only  .env"), "{text}");
    let warnings = String::from_utf8_lossy(&output.stderr);
    assert!(warnings.contains("`.env` matches nothing"), "{warnings}");
}
