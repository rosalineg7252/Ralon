//! One function per subcommand. Each returns the process exit code.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Result};

use crate::enforce::{self, Backend, Plan};
use crate::matcher::{relative_path, Matcher};
use crate::policy::{self, Policy, POLICY_FILE};
use crate::scan::{self, ProtectedPath};

pub const OK: u8 = 0;
/// A path the policy protects, or a command the policy stopped.
pub const VIOLATION: u8 = 1;

pub fn init(directory: &Path, force: bool) -> Result<ExitCode> {
    let target = directory.join(POLICY_FILE);
    if target.exists() && !force {
        bail!(
            "{} already exists (use --force to overwrite)",
            target.display()
        );
    }
    std::fs::write(&target, policy::TEMPLATE)?;
    println!("wrote {}", target.display());
    println!("edit it, then run: agent-lock run -- <your agent>");
    Ok(ExitCode::from(OK))
}

pub fn check(directory: &Path, paths: &[PathBuf]) -> Result<ExitCode> {
    let policy = Policy::load(directory)?;
    let matcher = Matcher::new(&policy.patterns)?;

    if paths.is_empty() {
        return list_protected(&policy, &matcher);
    }

    let mut protected_count = 0;
    for path in paths {
        let absolute = policy::absolute(&directory.join(path))?;
        match relative_path(&policy.root, &absolute) {
            Some(relative) => match matcher.matched_pattern(&relative) {
                Some(pattern) => {
                    protected_count += 1;
                    println!("locked    {relative}  (matches `{pattern}`)");
                }
                None => println!("writable  {relative}"),
            },
            None => println!("outside   {}", path.display()),
        }
    }

    Ok(ExitCode::from(if protected_count > 0 {
        VIOLATION
    } else {
        OK
    }))
}

fn list_protected(policy: &Policy, matcher: &Matcher) -> Result<ExitCode> {
    let found = scan::scan(&policy.root, matcher)?;
    for path in &found {
        let suffix = if path.is_dir { "/" } else { "" };
        println!(
            "locked    {}{}  (matches `{}`)",
            path.relative, suffix, path.pattern
        );
    }
    warn_about_unmatched(policy, &found);
    Ok(ExitCode::from(OK))
}

pub fn status(directory: &Path) -> Result<ExitCode> {
    let policy = Policy::load(directory)?;
    let matcher = Matcher::new(&policy.patterns)?;
    let found = scan::scan(&policy.root, &matcher)?;

    println!("policy     {}", policy.file.display());
    println!("root       {}", policy.root.display());
    println!("version    {}", policy.version);
    println!(
        "patterns   {} declared (+1 implicit: {POLICY_FILE})",
        policy.declared_patterns().len()
    );
    println!(
        "protected  {} currently on disk",
        count(found.len(), "path", "paths")
    );

    println!("backends");
    for (backend, availability) in enforce::availability() {
        println!("  {backend:<9}{availability}");
    }

    warn_about_unmatched(&policy, &found);
    Ok(ExitCode::from(OK))
}

pub fn run(
    directory: &Path,
    backend: Backend,
    dry_run: bool,
    quiet: bool,
    command: &[OsString],
) -> Result<ExitCode> {
    let policy = Policy::load(directory)?;
    let matcher = Matcher::new(&policy.patterns)?;
    let found = scan::scan(&policy.root, &matcher)?;
    let protected = scan::canonical_targets(&found)?;
    // The protected paths are canonical, so the root has to be too or it will
    // not look like their ancestor.
    let root = std::fs::canonicalize(&policy.root)?;

    let resolved = enforce::resolve(backend);

    if dry_run {
        let display_backend = match (&resolved, backend) {
            (Ok(resolved), _) => *resolved,
            // Nothing is enforceable here, but the plan is still worth showing.
            (Err(_), Backend::Auto) => Backend::Landlock,
            (Err(_), requested) => requested,
        };
        let plan = Plan::build(display_backend, &root, protected);
        print_plan(&policy, &found, &plan, command);
        warn_about_unmatched(&policy, &found);
        if let Err(error) = resolved {
            println!();
            println!("would fail: {error:#}");
            return Ok(ExitCode::from(VIOLATION));
        }
        return Ok(ExitCode::from(OK));
    }

    let plan = Plan::build(resolved?, &root, protected);

    if !quiet {
        eprintln!(
            "agent-lock: {} locked via the {} backend",
            count(plan.protected.len(), "path", "paths"),
            plan.backend
        );
        warn_about_unmatched(&policy, &found);
    }

    // Only returns if enforcement or exec failed.
    Err(enforce::enforce_and_exec(&plan, command))
}

fn print_plan(policy: &Policy, found: &[ProtectedPath], plan: &Plan, command: &[OsString]) {
    let rendered: Vec<String> = command
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect();

    println!("root       {}", policy.root.display());
    println!("backend    {}", plan.backend);
    println!("command    {}", rendered.join(" "));
    println!("protected  {}", count(found.len(), "path", "paths"));
    for path in found {
        let suffix = if path.is_dir { "/" } else { "" };
        println!("  read-only  {}{}", path.relative, suffix);
    }

    if !plan.pinned.is_empty() {
        println!(
            "pinned     {}, which cannot be renamed or removed",
            count(plan.pinned.len(), "directory", "directories")
        );
        for directory in &plan.pinned {
            println!("  mount point  {}", directory.display());
        }
    }

    if let Some(carve) = &plan.carve {
        println!(
            "landlock   {}, {} create-restricted",
            count(carve.granted.len(), "grant", "grants"),
            count(carve.restricted.len(), "directory", "directories"),
        );
        for directory in &carve.restricted {
            println!("  no new entries in  {}", directory.display());
        }
    }
}

fn count(amount: usize, singular: &str, plural: &str) -> String {
    if amount == 1 {
        format!("{amount} {singular}")
    } else {
        format!("{amount} {plural}")
    }
}

fn warn_about_unmatched(policy: &Policy, found: &[ProtectedPath]) {
    for pattern in scan::unmatched_patterns(policy.declared_patterns(), found) {
        eprintln!(
            "agent-lock: warning: `{pattern}` matches nothing on disk, so there is nothing to lock"
        );
    }
}
