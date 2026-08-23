//! End-to-end tests for the parts of the CLI that work on every platform.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_agent-lock");

/// A throwaway project directory, removed on drop.
struct Project {
    root: PathBuf,
}

impl Project {
    fn new(policy: Option<&str>) -> Project {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "agent-lock-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(unique);
        fs::create_dir_all(&root).unwrap();

        let project = Project { root };
        if let Some(policy) = policy {
            project.write("agent.lock", policy);
        }
        project
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(BINARY)
            .arg("--dir")
            .arg(&self.root)
            .args(arguments)
            .output()
            .expect("failed to run agent-lock")
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
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

const POLICY: &str = "version: 1\nprotect:\n  - src/index.tsx\n  - .env\n  - config/**\n";

#[test]
fn init_writes_a_usable_policy_and_refuses_to_clobber_it() {
    let project = Project::new(None);

    let created = project.run(&["init"]);
    assert_eq!(code(&created), 0, "{}", stderr(&created));
    assert!(project.root.join("agent.lock").is_file());

    let again = project.run(&["init"]);
    assert_eq!(code(&again), 2);
    assert!(
        stderr(&again).contains("already exists"),
        "{}",
        stderr(&again)
    );

    // The generated file must be valid input for the tool itself.
    let status = project.run(&["status"]);
    assert_eq!(code(&status), 0, "{}", stderr(&status));
}

#[test]
fn check_reports_protected_paths_and_exits_nonzero() {
    let project = Project::new(Some(POLICY));

    let protected = project.run(&["check", "src/index.tsx"]);
    assert_eq!(code(&protected), 1);
    assert!(
        stdout(&protected).contains("locked"),
        "{}",
        stdout(&protected)
    );

    let writable = project.run(&["check", "src/App.tsx"]);
    assert_eq!(code(&writable), 0);
    assert!(stdout(&writable).contains("writable"));
}

#[test]
fn check_protects_the_policy_file_itself() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["check", "agent.lock"]);
    assert_eq!(code(&output), 1, "{}", stdout(&output));
}

#[test]
fn check_covers_paths_inside_a_protected_directory() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["check", "config/deep/db.yaml", "src/App.tsx"]);
    assert_eq!(code(&output), 1);
    let text = stdout(&output);
    assert!(text.contains("locked    config/deep/db.yaml"), "{text}");
    assert!(text.contains("writable  src/App.tsx"), "{text}");
}

#[test]
fn check_notices_paths_outside_the_project() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["check", "../elsewhere.txt"]);
    assert_eq!(code(&output), 0);
    assert!(stdout(&output).contains("outside"), "{}", stdout(&output));
}

#[test]
fn check_without_arguments_lists_what_exists() {
    let project = Project::new(Some(POLICY));
    project.write("src/index.tsx", "locked\n");
    project.write("src/App.tsx", "writable\n");
    project.write("config/db.yaml", "locked\n");

    let output = project.run(&["check"]);
    let text = stdout(&output);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(text.contains("agent.lock"), "{text}");
    assert!(text.contains("src/index.tsx"), "{text}");
    // A protected directory is listed once, not expanded entry by entry.
    assert!(text.contains("config/"), "{text}");
    assert!(!text.contains("config/db.yaml"), "{text}");
    assert!(!text.contains("App.tsx"), "{text}");
    // `.env` is declared but absent, so there is nothing to lock.
    assert!(
        stderr(&output).contains("`.env` matches nothing"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn commands_find_the_policy_from_a_subdirectory() {
    let project = Project::new(Some(POLICY));
    project.write("src/deep/nested.txt", "x\n");

    let output = Command::new(BINARY)
        .arg("--dir")
        .arg(project.root.join("src").join("deep"))
        .args(["check", "../index.tsx"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
}

#[test]
fn missing_policy_is_an_error_not_a_silent_pass() {
    let project = Project::new(None);
    let output = project.run(&["check", "anything.txt"]);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("no agent.lock"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_broken_policy_stops_everything() {
    let project = Project::new(Some("version: 1\nprotect:\n  - ../escape\n"));
    let output = project.run(&["check", "src/App.tsx"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains(".."), "{}", stderr(&output));
}

#[test]
fn dry_run_describes_what_would_be_locked() {
    let project = Project::new(Some(POLICY));
    project.write("src/index.tsx", "locked\n");
    project.write("config/db.yaml", "locked\n");

    let output = project.run(&["run", "--dry-run", "--", "echo", "hello"]);
    let text = stdout(&output);
    assert!(text.contains("read-only  src/index.tsx"), "{text}");
    assert!(text.contains("read-only  config/"), "{text}");
    assert!(text.contains("read-only  agent.lock"), "{text}");
    assert!(text.contains("echo hello"), "{text}");

    // The plan is always shown. Whether it could be enforced depends on the
    // kernel, and the tool must say which instead of pretending either way.
    match code(&output) {
        0 => assert!(!text.contains("would fail"), "{text}"),
        1 => assert!(text.contains("would fail"), "{text}"),
        other => panic!("unexpected exit code {other}\n{text}\n{}", stderr(&output)),
    }
}

#[test]
fn status_lists_backends() {
    let project = Project::new(Some(POLICY));
    let output = project.run(&["status"]);
    let text = stdout(&output);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(text.contains("backends"), "{text}");
    assert!(text.contains("mount"), "{text}");
    assert!(text.contains("landlock"), "{text}");
    assert!(text.contains("version    1"), "{text}");
}

#[test]
fn run_off_linux_refuses_rather_than_running_unprotected() {
    if cfg!(target_os = "linux") {
        return;
    }
    let project = Project::new(Some(POLICY));
    project.write("src/index.tsx", "locked\n");

    let marker = project.root.join("should-not-exist.txt");
    let output = project.run(&[
        "run",
        "--",
        "cmd",
        "/c",
        &format!("type nul > {}", marker.display()),
    ]);

    assert_eq!(code(&output), 2, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("Linux-only"),
        "{}",
        stderr(&output)
    );
    assert!(!marker.exists(), "the command must not have run");
}

#[test]
fn the_binary_reports_a_version() {
    let output = Command::new(BINARY).arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}
