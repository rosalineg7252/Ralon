//! `install once → create agent.lock → enforced`, tested against the real thing.
//!
//! These drive the actual binary against actual directories and then **read the
//! files back**. Not one assertion here trusts an exit code: `del` returns 0
//! when it failed and `>` returns 0 when it was refused, and two bugs in this
//! project's history were "attack refused" reported by a check that never opened
//! the file.
//!
//! Every test gets its own state directory and its own tree of repositories, so
//! they can run in parallel and so nothing here can disturb a supervisor the
//! developer has installed for real. For the same reason nothing in this file
//! runs `ralon install` or `ralon uninstall`: registering a logon task or a
//! LaunchAgent is machine-wide by nature, and a test suite that deregistered the
//! developer's own supervisor would be a worse bug than any it could catch. The
//! registration itself is unit-tested in `service/`, where the document it
//! produces can be inspected without installing it.

// Most of the harness below drives enforcement, and on Linux there is none —
// `install` refuses there, so those tests are compiled out and their helpers
// with them. Kept in one file rather than split, because the Linux tests assert
// on the *refusal*, and the two belong next to each other: whichever platform
// you are reading this on, the answer for the other one is on the same page.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_ralon");

const POLICY: &str = "version: 1\nprotect:\n  - .env\n  - src/index.tsx\n  - config/**\n";

/// A machine with Ralon set up on it: a state directory and a place where the
/// developer keeps code.
struct Machine {
    home: PathBuf,
    code: PathBuf,
    projects: std::cell::RefCell<Vec<PathBuf>>,
}

impl Machine {
    fn new() -> Machine {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ralon-sup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let home = root.join("state");
        let code = root.join("code");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&code).unwrap();

        let machine = Machine {
            home,
            code,
            projects: std::cell::RefCell::new(Vec::new()),
        };
        // What `ralon install` writes. Written directly so the test never has to
        // register anything with the operating system.
        machine.configure(std::slice::from_ref(&machine.code));
        machine
    }

    fn configure(&self, roots: &[PathBuf]) {
        let mut text = String::from("roots:\n");
        for root in roots {
            let canonical = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            text.push_str(&format!("- {}\n", yaml(&canonical)));
        }
        text.push_str("max_depth: 8\n");
        fs::write(self.home.join("config.yaml"), text).unwrap();
    }

    /// A repository, with or without a policy in it.
    fn repository(&self, name: &str, policy: Option<&str>) -> Repository {
        let root = self.code.join(name);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(root.join(".env"), "SECRET=original").unwrap();
        fs::write(root.join("src/index.tsx"), "original").unwrap();
        fs::write(root.join("src/App.tsx"), "original").unwrap();
        fs::write(root.join("config/db.yaml"), "original").unwrap();

        // Canonicalized and then un-prefixed. `fs::canonicalize` on Windows
        // returns the verbatim form, `\\?\C:\...`, which is the right identity
        // for the supervisor and a path `cmd.exe` cannot open — and every attack
        // in this file goes through `cmd`, so a verbatim path here would make
        // the attacks fail for the wrong reason and the tests pass for it.
        let repository = Repository {
            root: plain(&fs::canonicalize(&root).unwrap()),
            home: self.home.clone(),
        };
        self.projects.borrow_mut().push(repository.root.clone());
        if let Some(policy) = policy {
            repository.declare(policy);
        }
        repository
    }

    fn ralon(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .args(arguments)
            .env("RALON_HOME", &self.home)
            .output()
            .expect("failed to run ralon")
    }

    /// One pass of the supervisor, as the daemon would do it.
    fn tick(&self) -> Output {
        self.ralon(&["daemon", "--once"])
    }

    fn recorded(&self) -> String {
        fs::read_to_string(self.home.join("workspaces.json")).unwrap_or_default()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        // Releasing before deleting, in that order and unconditionally. A guard
        // holds its files open, so a temp directory with one still running
        // cannot be removed on Windows — and the leftover process would hold the
        // test binary's own `ralon.exe` open too, which is how a suite starts
        // failing to rebuild for reasons nobody can see.
        for root in self.projects.borrow().iter() {
            let _ = Command::new(BINARY)
                .arg("--dir")
                .arg(root)
                .args(["guard", "--stop"])
                .env("RALON_HOME", &self.home)
                .output();
        }
        if let Some(parent) = self.home.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

struct Repository {
    root: PathBuf,
    home: PathBuf,
}

impl Repository {
    fn declare(&self, policy: &str) {
        fs::write(self.root.join("agent.lock"), policy).unwrap();
    }

    fn undeclare(&self) {
        fs::remove_file(self.root.join("agent.lock")).unwrap();
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn contents(&self, relative: &str) -> String {
        fs::read_to_string(self.path(relative)).unwrap_or_default()
    }

    fn ralon(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .arg("--dir")
            .arg(&self.root)
            .args(arguments)
            .env("RALON_HOME", &self.home)
            .current_dir(&self.root)
            .output()
            .expect("failed to run ralon")
    }

    /// Whether an ordinary write to `relative` gets through.
    ///
    /// Run in a separate shell process on purpose: the whole claim being tested
    /// is that enforcement reaches a process Ralon never started and that has
    /// never heard of it. Reading the file back afterwards is the assertion —
    /// the shell's exit code is not evidence of anything.
    fn writable(&self, relative: &str) -> bool {
        let before = self.contents(relative);
        let marker = "OVERWRITTEN-BY-AN-AGENT";
        shell(&self.root, &redirect(marker, &self.path(relative)));
        let after = self.contents(relative);
        if after.trim() == marker {
            // Put it back, so one probe does not change the outcome of the next.
            let _ = fs::write(self.path(relative), before);
            return true;
        }
        false
    }

    /// Whether a new file can be created at `relative`.
    fn creatable(&self, relative: &str) -> bool {
        let path = self.path(relative);
        let _ = fs::remove_file(&path);
        shell(&self.root, &redirect("NEW", &path));
        let created = path.is_file();
        let _ = fs::remove_file(&path);
        created
    }
}

/// A shell command, in the platform's own shell, outside Ralon entirely.
///
/// `raw_arg` on Windows, not `arg`. `Command` quotes arguments the way a C
/// runtime expects, escaping an embedded `"` as `\"` — and `cmd.exe` does not
/// parse its command line that way, so it sees a literal backslash and the
/// redirect never happens. The attack then does nothing, the file is unchanged,
/// and a test that reads the file back concludes it was refused. Every
/// enforcement assertion in this file would have passed against a Ralon that
/// enforced nothing at all.
fn shell(directory: &Path, command: &str) {
    #[cfg(windows)]
    let mut process = {
        use std::os::windows::process::CommandExt;
        let mut process = Command::new("cmd");
        process.raw_arg("/c").raw_arg(command);
        process
    };

    #[cfg(not(windows))]
    let mut process = {
        let mut process = Command::new("sh");
        process.args(["-c", command]);
        process
    };

    let _ = process.current_dir(directory).output();
}

fn redirect(text: &str, path: &Path) -> String {
    format!("echo {text}> \"{}\"", path.display())
}

/// Quotes a path for the config file. A Windows path is full of backslashes,
/// which YAML reads as escapes inside double quotes and leaves alone in single.
fn yaml(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

/// Strips the `\\?\` a canonicalized Windows path carries, so the result is
/// something an ordinary shell can open.
fn plain(path: &Path) -> PathBuf {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process was killed")
}

// ---------------------------------------------------------------------------
// Discovery and policy handling. Platform-independent in shape, but every one
// of these drives a real supervisor pass, and on Linux there is no supervisor to
// drive — `daemon` refuses there, which `without_a_supervisor` covers instead.
// ---------------------------------------------------------------------------

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_policy_outside_every_watched_directory_is_never_enforced() {
    let machine = Machine::new();
    // Watching a directory that exists but holds no projects.
    let empty = machine.code.join("watched");
    fs::create_dir_all(&empty).unwrap();
    machine.configure(&[empty]);

    // A repository with a perfectly good policy, somewhere nobody registered —
    // the shape of an `agent.lock` that arrived inside a downloaded archive.
    let elsewhere = machine.repository("unwatched", Some(POLICY));

    machine.tick();
    assert!(
        !machine.recorded().contains("unwatched"),
        "a policy outside every scan root was picked up: {}",
        machine.recorded()
    );

    // And says so rather than looking protected.
    let status = elsewhere.ralon(&["status"]);
    assert!(
        !stdout(&status).contains("enforced by the supervisor"),
        "{}",
        stdout(&status)
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_malformed_policy_is_reported_and_never_looks_enforced() {
    let machine = Machine::new();
    let repository = machine.repository("broken", Some("version: 1\nprotect: [oh no: ["));

    let tick = machine.tick();
    // Not a crash, and not silence.
    assert_eq!(code(&tick), 0, "{}", stderr(&tick));
    let reported = format!("{}{}", stdout(&tick), stderr(&tick));
    assert!(
        reported.contains("cannot enforce"),
        "a policy that does not parse was not reported: {reported}"
    );
    assert!(
        machine.recorded().contains("failed"),
        "{}",
        machine.recorded()
    );

    // The crucial half: it must not read as protected anywhere. `status` cannot
    // even parse the policy, so it fails and names the line — which is a better
    // answer than a summary, and is emphatically not a clean report.
    let status = repository.ralon(&["status"]);
    assert_ne!(
        code(&status),
        0,
        "status was happy about a policy it cannot read: {}",
        stdout(&status)
    );
    assert!(
        stderr(&status).contains("failed to parse"),
        "{}",
        stderr(&status)
    );
    assert!(!stdout(&status).contains("enforced"), "{}", stdout(&status));
}

#[test]
#[cfg(any(windows, target_os = "macos"))]
fn a_malformed_policy_locks_nothing_rather_than_locking_everything() {
    // "Fail safely" has two readings and only one of them is right. A policy
    // that cannot be parsed names no paths, so there is nothing to protect and
    // nothing is protected — loudly. Falling *closed* here would mean freezing
    // a repository on the strength of a file nobody could read, which is a
    // worse outcome than the one being avoided and impossible to diagnose.
    //
    // The case where this would matter most cannot arise: a workspace that is
    // already enforced has its own `agent.lock` locked, so nothing can corrupt
    // it while enforcement is in place.
    let machine = Machine::new();
    let repository = machine.repository("broken", Some("version: 1\nprotect: [oh no: ["));
    machine.tick();

    assert!(
        repository.writable(".env"),
        "an unreadable policy left files locked, with no way to find out why"
    );
    assert!(
        machine.recorded().contains("failed"),
        "{}",
        machine.recorded()
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_broken_policy_that_gets_fixed_is_picked_up() {
    let machine = Machine::new();
    let repository = machine.repository("fixed", Some("version: 9\nprotect: []"));

    machine.tick();
    assert!(
        machine.recorded().contains("failed"),
        "{}",
        machine.recorded()
    );

    repository.declare(POLICY);
    machine.tick();
    assert!(
        machine.recorded().contains("enforced"),
        "a corrected policy was not picked up: {}",
        machine.recorded()
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_policy_file_carries_no_machine_state() {
    // `agent.lock` is committed to Git and shared between machines, so the
    // supervisor must never write to it. Everything it learns lives in its own
    // state directory.
    let machine = Machine::new();
    let repository = machine.repository("portable", Some(POLICY));

    machine.tick();

    assert_eq!(
        repository.contents("agent.lock"),
        POLICY,
        "the supervisor modified agent.lock"
    );
    let recorded = machine.recorded();
    assert!(
        recorded.contains("portable"),
        "state should live in the state directory: {recorded}"
    );
}

// ---------------------------------------------------------------------------
// Linux, where the honest answer is no.
// ---------------------------------------------------------------------------

#[cfg(not(any(windows, target_os = "macos")))]
mod without_a_supervisor {
    use super::*;

    #[test]
    fn install_refuses_and_explains_why() {
        let machine = Machine::new();
        let attempt = machine.ralon(&["install", "--watch", machine.code.to_str().unwrap()]);

        assert_ne!(
            code(&attempt),
            0,
            "install claimed to work: {}",
            stdout(&attempt)
        );
        let said = stderr(&attempt);
        // Not merely "unsupported" — the reason, and what to do instead.
        assert!(said.contains("inherited"), "{said}");
        assert!(said.contains("ralon run"), "{said}");
        assert!(
            !said.contains("systemd"),
            "a systemd unit would start and enforce nothing: {said}"
        );
    }

    #[test]
    fn the_daemon_refuses_to_run_rather_than_watching_files_it_cannot_protect() {
        let machine = Machine::new();
        let _repository = machine.repository("app", Some(POLICY));

        let attempt = machine.tick();
        assert_ne!(
            code(&attempt),
            0,
            "the daemon started on a platform where it can enforce nothing: {}",
            stdout(&attempt)
        );
        assert!(
            !machine.home.join("workspaces.json").exists(),
            "a workspace was recorded as being looked after by nothing"
        );
    }

    #[test]
    fn run_is_untouched_and_is_still_the_answer_here() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        let planned = repository.ralon(&["run", "--dry-run", "--", "sh", "-c", "true"]);
        assert_eq!(code(&planned), 0, "{}", stderr(&planned));
        assert!(
            stdout(&planned).contains("read-only"),
            "{}",
            stdout(&planned)
        );
    }
}

// ---------------------------------------------------------------------------
// Windows and macOS, where a background process can impose a restriction.
// ---------------------------------------------------------------------------

#[cfg(any(windows, target_os = "macos"))]
mod with_a_supervisor {
    use super::*;

    #[test]
    fn a_repository_with_a_policy_becomes_enforced_with_nothing_run_inside_it() {
        let machine = Machine::new();
        let repository = machine.repository("app", None);

        // No policy yet: an ordinary project, ordinary permissions.
        machine.tick();
        assert!(
            repository.writable(".env"),
            "a project with no policy should be writable"
        );

        // This is the entire user-facing gesture. No `ralon init`, no wrapper.
        repository.declare(POLICY);
        machine.tick();

        assert!(
            !repository.writable(".env"),
            ".env was still writable after the policy appeared"
        );
        assert!(
            !repository.writable("src/index.tsx"),
            "src/index.tsx was still writable"
        );
        assert!(
            !repository.writable("config/db.yaml"),
            "a file inside a protected directory was still writable"
        );
        assert!(
            !repository.writable("agent.lock"),
            "the policy could rewrite itself"
        );
        // And nothing beyond the policy was touched.
        assert!(
            repository.writable("src/App.tsx"),
            "an unprotected file stopped being writable"
        );
    }

    #[test]
    fn a_protected_directory_refuses_new_entries() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        assert!(
            !repository.creatable("config/slipped-in.yaml"),
            "a new file was created inside a protected directory"
        );
        assert!(
            repository.creatable("src/allowed.tsx"),
            "a new file could not be created in an unprotected directory"
        );
    }

    #[test]
    fn removing_the_policy_releases_the_workspace() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();
        assert!(!repository.writable(".env"));

        // The policy protects itself, so it cannot simply be deleted — which is
        // the point of it. `pause` is the supported way to get it back.
        assert!(
            repository
                .ralon(&["pause", "--indefinitely"])
                .status
                .success(),
            "pause failed"
        );
        repository.undeclare();

        machine.tick();
        assert!(
            repository.writable(".env"),
            "the workspace stayed enforced after its policy was deleted"
        );
        assert!(
            !machine.recorded().contains("\"app\""),
            "a workspace with no policy is still recorded: {}",
            machine.recorded()
        );
    }

    #[test]
    fn a_policy_deleted_while_the_supervisor_was_down_is_still_released() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        // Everything stops — the supervisor and the enforcement with it — and
        // the repository is deleted before anything starts again. The record in
        // the state directory is the only thing that still knows this workspace
        // existed.
        repository.ralon(&["guard", "--stop"]);
        repository.undeclare();

        let tick = machine.tick();
        assert_eq!(code(&tick), 0, "{}", stderr(&tick));
        assert!(
            !machine.recorded().contains("app"),
            "a deleted workspace was never cleaned up: {}",
            machine.recorded()
        );
        assert!(repository.writable(".env"), ".env stayed locked");
    }

    #[test]
    fn two_repositories_are_enforced_at_once_and_do_not_interfere() {
        let machine = Machine::new();
        let first = machine.repository("one", Some(POLICY));
        let second = machine.repository("two", Some("version: 1\nprotect:\n  - src/index.tsx\n"));
        machine.tick();

        // Each gets exactly its own policy, not the other's.
        assert!(!first.writable(".env"), "one/.env was writable");
        assert!(!first.writable("src/index.tsx"), "one/src/index.tsx");
        assert!(!second.writable("src/index.tsx"), "two/src/index.tsx");
        assert!(
            second.writable(".env"),
            "two/.env is not in two's policy and must stay writable"
        );

        // And releasing one leaves the other alone.
        assert!(second.ralon(&["pause", "--indefinitely"]).status.success());
        assert!(second.writable("src/index.tsx"), "two was not released");
        assert!(
            !first.writable("src/index.tsx"),
            "pausing one repository released another"
        );
    }

    #[test]
    fn a_repository_cloned_after_setup_is_picked_up() {
        let machine = Machine::new();
        let _existing = machine.repository("old", Some(POLICY));
        machine.tick();

        // The flow the whole feature exists for: the machine was set up once,
        // and this repository did not exist at the time.
        let cloned = machine.repository("cloned-later", Some(POLICY));
        machine.tick();

        assert!(
            !cloned.writable(".env"),
            "a repository cloned after install was not protected"
        );
    }

    #[test]
    fn restarting_the_supervisor_changes_nothing() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));

        machine.tick();
        let after_first = machine.recorded();

        // Each `daemon --once` is a fresh process reading the state back from
        // disk, which is exactly what a restart is.
        let second = machine.tick();
        let third = machine.tick();

        assert_eq!(code(&second), 0, "{}", stderr(&second));
        assert!(
            stdout(&third).contains("nothing to change"),
            "a restart re-did work that was already done: {}",
            stdout(&third)
        );
        assert_eq!(
            after_first,
            machine.recorded(),
            "the recorded state drifted across restarts"
        );
        assert!(
            !repository.writable(".env"),
            "enforcement lapsed on restart"
        );
    }

    #[test]
    fn enforcement_is_restored_after_the_machine_restarts() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();
        assert!(!repository.writable(".env"));

        // A reboot, faithfully: whatever was holding the files lets go, and the
        // state directory still says the workspace is enforced. On Windows that
        // is what actually happens — the guard is a process and processes do not
        // survive a restart. A supervisor that believed its own notes here would
        // come up, agree everything was fine, and protect nothing.
        repository.ralon(&["guard", "--stop"]);
        assert!(
            repository.writable(".env"),
            "the simulated reboot did not actually release anything, \
             so this test would pass without proving anything"
        );

        machine.tick();
        assert!(
            !repository.writable(".env"),
            "enforcement was not restored after a restart"
        );
    }

    #[test]
    fn enforcement_holds_against_many_agents_writing_at_once() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        // Twelve unrelated processes, none of them started by Ralon, all
        // hammering the same protected paths at the same time.
        let root = repository.root.clone();
        let workers: Vec<_> = (0..12)
            .map(|index| {
                let root = root.clone();
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        for target in [".env", "src/index.tsx", "agent.lock"] {
                            shell(
                                &root,
                                &redirect(&format!("AGENT{index}"), &root.join(target)),
                            );
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        assert_eq!(repository.contents(".env"), "SECRET=original");
        assert_eq!(repository.contents("src/index.tsx"), "original");
        assert_eq!(repository.contents("agent.lock"), POLICY);
    }

    #[test]
    fn enforcement_holds_however_the_write_is_attempted() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        // A hook covers an agent's own edit tools. None of these go anywhere
        // near one: a shell redirect, a delete, a rename, a rename *over* the
        // target, and a script written to disk and executed.
        let env = repository.path(".env");
        let index = repository.path("src/index.tsx");
        let decoy = repository.path("src/decoy.tsx");
        fs::write(&decoy, "DECOY").unwrap();

        #[cfg(windows)]
        let attacks = vec![
            format!("echo X> \"{}\"", env.display()),
            format!("del /f /q \"{}\"", env.display()),
            format!("move /y \"{}\" \"{}.bak\"", env.display(), env.display()),
            format!("move /y \"{}\" \"{}\"", decoy.display(), index.display()),
            format!("type \"{}\" > \"{}\"", decoy.display(), env.display()),
        ];
        #[cfg(not(windows))]
        let attacks = vec![
            format!("echo X> '{}'", env.display()),
            format!("rm -f '{}'", env.display()),
            format!("mv '{}' '{}.bak'", env.display(), env.display()),
            format!("mv '{}' '{}'", decoy.display(), index.display()),
            format!("cat '{}' > '{}'", decoy.display(), env.display()),
        ];

        for attack in &attacks {
            shell(&repository.root, attack);
            assert_eq!(
                repository.contents(".env"),
                "SECRET=original",
                "`{attack}` got through to .env"
            );
            assert_eq!(
                repository.contents("src/index.tsx"),
                "original",
                "`{attack}` got through to src/index.tsx"
            );
        }

        // The same again, from a script file rather than an inline command, so
        // nothing about this depends on how the shell was invoked.
        #[cfg(windows)]
        let (script, runner) = ("attack.cmd", "cmd");
        #[cfg(not(windows))]
        let (script, runner) = ("attack.sh", "sh");
        let script = repository.root.join(script);
        fs::write(&script, attacks.join("\n")).unwrap();

        let mut process = Command::new(runner);
        #[cfg(windows)]
        process.arg("/c");
        process.arg(&script);
        let _ = process.current_dir(&repository.root).output();

        assert_eq!(repository.contents(".env"), "SECRET=original");
        assert_eq!(repository.contents("src/index.tsx"), "original");
    }

    #[test]
    fn pause_hands_the_policy_back_and_resume_takes_it_again() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();
        assert!(!repository.writable("agent.lock"));

        let paused = repository.ralon(&["pause", "--indefinitely"]);
        assert_eq!(code(&paused), 0, "{}", stderr(&paused));
        // The command must not return until the file is genuinely writable, or
        // `ralon pause && $EDITOR agent.lock` races it.
        assert!(
            repository.writable("agent.lock"),
            "pause returned before releasing the policy file"
        );

        // A pause is a hole in the protection and has to be visible as one.
        let status = repository.ralon(&["status"]);
        assert!(
            stdout(&status).contains("PAUSED"),
            "a paused workspace did not say so: {}",
            stdout(&status)
        );

        let resumed = repository.ralon(&["resume"]);
        assert_eq!(code(&resumed), 0, "{}", stderr(&resumed));
        assert!(
            !repository.writable("agent.lock"),
            "resume reported success without restoring enforcement"
        );
    }

    #[test]
    fn a_paused_workspace_is_not_re_enforced_until_it_expires() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        repository.ralon(&["pause", "--indefinitely"]);
        // The supervisor keeps running while a workspace is paused and must
        // leave it alone rather than immediately taking it back.
        machine.tick();
        assert!(
            repository.writable("agent.lock"),
            "a tick re-enforced a paused workspace"
        );

        // An expired pause is over without anyone doing anything: rewrite the
        // deadline into the past, which is what the clock would have done.
        let recorded = machine
            .recorded()
            .replace(r#""until": null"#, r#""until": 1"#);
        assert!(
            recorded.contains(r#""until": 1"#),
            "the deadline was never rewritten, so this test proves nothing: {recorded}"
        );
        fs::write(machine.home.join("workspaces.json"), recorded).unwrap();

        machine.tick();
        assert!(
            !repository.writable("agent.lock"),
            "a pause that had run out was not taken back"
        );
    }

    #[test]
    fn status_reports_the_supervisor_and_the_workspace_separately() {
        let machine = Machine::new();
        let repository = machine.repository("app", Some(POLICY));
        machine.tick();

        let status = repository.ralon(&["status"]);
        let said = stdout(&status);
        // "A service is registered" and "this project is protected" are
        // different claims, and only the second one is about these files.
        assert!(said.contains("supervisor"), "{said}");
        assert!(said.contains("enforced by the supervisor"), "{said}");
    }
}
