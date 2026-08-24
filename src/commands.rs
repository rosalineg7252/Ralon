//! One function per subcommand. Each returns the process exit code.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Result};

use crate::audit;
use crate::cli::Agent;
use crate::enforce::{self, Backend, Plan};
use crate::hook;
use crate::matcher::{relative_path, Matcher};
use crate::policy::{self, Policy, POLICY_FILE};
use crate::scan::{self, ProtectedPath};

pub const OK: u8 = 0;
/// A path the policy protects, or a command the policy stopped.
pub const VIOLATION: u8 = 1;
/// What a hook returns to refuse an edit. Every supported agent reads exit 2
/// as "blocked"; Cursor treats any other non-zero code as fail-open.
pub const BLOCKED: u8 = 2;

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
    println!("edit it, then run: ralon run -- <your agent>");
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
    let availability = enforce::availability();
    for (backend, status) in &availability {
        println!("  {backend:<9}{status}");
    }

    // "unavailable" states a fact and leaves the wrong conclusion available:
    // that a policy which lists protected paths is protecting them. It is not.
    if !availability.iter().any(|(_, status)| status.is_available()) {
        let hooked = [
            ".claude/settings.json",
            ".cursor/hooks.json",
            ".opencode/plugins/ralon.js",
        ]
        .iter()
        .any(|relative| policy.root.join(relative).is_file());
        println!();
        println!("Nothing on this machine can stop an agent from writing to those paths.");
        println!("`ralon run` will refuse to start rather than pretend otherwise.");
        if hooked {
            println!("An agent hook is installed, which refuses those agents' own edit tools.");
        } else {
            println!("  ralon hook install    refuse agents' edit tools (a courtesy layer)");
        }
        println!("  wsl                   run the agent where the kernel can enforce");
    }

    warn_about_unmatched(&policy, &found);
    warn_about_weaknesses(&policy, &found);
    Ok(ExitCode::from(OK))
}

pub fn hook_install(directory: &Path, agent: Agent, dry_run: bool) -> Result<ExitCode> {
    // Install against the project the policy governs, not merely the working
    // directory, so the hook lands beside agent.lock.
    let root = Policy::load(directory)
        .map(|policy| policy.root)
        .unwrap_or_else(|_| directory.to_path_buf());

    let installed = hook::install_for(&root, agent, dry_run)?;
    if dry_run {
        return Ok(ExitCode::from(OK));
    }

    for entry in &installed {
        println!(
            "{} {}",
            if entry.replaced { "updated" } else { "wrote" },
            entry.path.display()
        );
    }
    println!();
    println!("Those agents will now be refused when they edit a protected path.");
    println!("This is a courtesy layer: it covers an agent's own edit tools, not");
    println!("a shell command it runs. Only `ralon run` on Linux is enforcement —");
    println!("and that works for every agent, including ones with no hooks at all.");
    Ok(ExitCode::from(OK))
}

pub fn hook_check(directory: &Path) -> Result<ExitCode> {
    // A hook that fails loudly stops the agent working; one that fails open
    // stops protecting. Only a definite match refuses.
    let decision = hook::check(directory)?;

    if let Some(rendered) = decision.render() {
        // The JSON is what Claude Code and Cursor read; the exit code is what
        // Cursor falls back to and what the OpenCode plugin inspects. Emitting
        // both is what lets one command serve every agent.
        println!("{rendered}");
        if let Some(reason) = decision.reason() {
            eprintln!("ralon: {reason}");
        }
        return Ok(ExitCode::from(BLOCKED));
    }
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
            "ralon: {} locked via the {} backend",
            count(plan.protected.len(), "path", "paths"),
            plan.backend
        );
        warn_about_unmatched(&policy, &found);
        warn_about_weaknesses(&policy, &found);
    }

    // On Linux this never returns: the process becomes the command. On Windows
    // it returns the command's exit status once the locks have been released.
    enforce::enforce_and_exec(&plan, command)
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

/// Conditions that weaken the policy without breaking it. Printed before the
/// agent starts, because afterwards there is nothing to be done about them.
fn warn_about_weaknesses(policy: &Policy, found: &[ProtectedPath]) {
    for finding in audit::audit(&policy.root, found) {
        eprintln!("ralon: warning: {} {}", finding.subject, finding.detail);
    }
}

fn warn_about_unmatched(policy: &Policy, found: &[ProtectedPath]) {
    for pattern in scan::unmatched_patterns(policy.declared_patterns(), found) {
        eprintln!(
            "ralon: warning: `{pattern}` matches nothing on disk, so there is nothing to lock"
        );
    }
}
