//! One function per subcommand. Each returns the process exit code.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use crate::audit;
use crate::cli::Agent;
use crate::enforce::{self, Backend, Plan};
use crate::hook;
use crate::matcher::{relative_path, Matcher};
use crate::policy::{self, Policy, POLICY_FILE};
use crate::scan::{self, ProtectedPath};
use crate::service;
use crate::supervisor::{self, registry, single, Supervisor};

pub const OK: u8 = 0;
/// A path the policy protects, or a command the policy stopped.
pub const VIOLATION: u8 = 1;
/// What a hook returns to refuse an edit. Every supported agent reads exit 2
/// as "blocked"; Cursor treats any other non-zero code as fail-open.
pub const BLOCKED: u8 = 2;

pub fn init(directory: &Path, force: bool, no_hooks: bool) -> Result<ExitCode> {
    let target = directory.join(POLICY_FILE);
    if target.exists() && !force {
        bail!(
            "{} already exists (use --force to overwrite)",
            target.display()
        );
    }
    std::fs::write(&target, policy::TEMPLATE)?;
    println!("wrote {}", target.display());

    // Hooks are configuration, not a process: writing them here costs the user
    // nothing and means the agents that *can* be told about the policy already
    // have been. What `init` deliberately does not do is start anything — the
    // policy it just wrote is a template nobody has edited yet, and a guard
    // holding a snapshot of it would protect the wrong paths convincingly.
    if !no_hooks {
        for entry in hook::install_for(directory, Agent::All, false)? {
            println!(
                "{} {}",
                if entry.replaced { "updated" } else { "wrote" },
                entry.path.display()
            );
        }
    }

    println!();
    println!("Now edit {POLICY_FILE}, then protect it:");
    if enforce::guard::AVAILABLE {
        println!("  ralon guard --detach   every process on this machine is refused");
        println!("  ralon guard --stop     hand the files back");
    } else {
        println!("  ralon run -- <your agent>   the agent and everything it spawns");
    }
    println!();
    print_what_a_refusal_looks_like();
    println!();
    println!("If this is useful, a star helps other people find it:");
    println!("  https://github.com/stoneware-dev/Ralon");
    Ok(ExitCode::from(OK))
}

/// Says in advance what enforcement looks like from the other side.
///
/// The hook is the only refusal whose wording belongs to Ralon. Everywhere else
/// the message is made by whatever the agent writes with, from an error code
/// Ralon caused but does not own — Node renders a Windows sharing violation as
/// `EBUSY: resource busy or locked`, which reads like a corrupt file rather
/// than a policy. There is no interception point that would fix that, so the
/// remaining honest move is to tell the developer beforehand, once, that the
/// confusing error is the tool working.
fn print_what_a_refusal_looks_like() {
    let errors = if cfg!(windows) {
        "`EBUSY: resource busy or locked`, or `Access is denied`"
    } else if cfg!(target_os = "macos") {
        "`EPERM: operation not permitted`"
    } else {
        "`EROFS: read-only file system`, or `EACCES: permission denied`"
    };
    println!("An agent that reaches a protected path reports");
    println!("  {errors}");
    println!("which is Ralon refusing the write, not a damaged file. Agents with a");
    println!("hook installed are told that in words instead.");
}

/// Sets the machine up once, so that a project is protected by containing an
/// `agent.lock` rather than by anyone running a command in it.
pub fn install(
    scope: &[PathBuf],
    depth: Option<usize>,
    no_hooks: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    if !service::SUPPORTED {
        bail!("{}", service::unsupported_reason());
    }

    let mut supervisor = Supervisor::load()?;
    let executable = std::env::current_exe().context("could not find the ralon executable")?;
    let home = registry::home()?;

    // The home directory is a *first-run* default, not a default applied every
    // time. Someone whose only scope is D:\Projects has said where their code
    // is; handing them C:\Users\... back on every re-install would be arguing
    // with them.
    let requested = if scope.is_empty() && supervisor.registry().config.roots.is_empty() {
        vec![registry::user_home().context(
            "could not find your home directory — pass --scope with a directory instead",
        )?]
    } else {
        scope.to_vec()
    };
    let roots = canonical_directories(&requested)?;

    if dry_run {
        println!("state      {}", home.display());
        println!("supervisor {}", executable.display());
        for root in &roots {
            println!("scope      {}", registry::display(root));
        }
        println!(
            "depth      {}",
            depth.unwrap_or(registry::DEFAULT_MAX_DEPTH)
        );
        println!("hooks      {}", if no_hooks { "no" } else { "yes" });
        println!();
        println!("Nothing was registered.");
        return Ok(ExitCode::from(OK));
    }

    // Additive. Re-running `install` must never drop a scope: someone who has
    // added D:\Projects and then runs `ralon install` again to repair a service
    // registration would otherwise silently lose it and find out weeks later,
    // from an agent that edited something it should not have.
    supervisor.add_scopes(&roots, depth, !no_hooks)?;

    // Enforced before the service is registered, and by this process. The
    // developer who just ran `install` is owed protection for the projects that
    // already exist, now, with the result on the screen — not whenever a service
    // they cannot see gets round to its first pass.
    let started = supervisor.tick(true)?;

    let registration = service::install(&executable, &home)?;

    println!(
        "wrote      {}",
        supervisor.registry().config_path().display()
    );
    for root in &supervisor.registry().config.roots {
        println!("scope      {}", registry::display(root));
    }
    println!("registered {}", registration.mechanism);
    if let Some(path) = &registration.path {
        println!("           {}", path.display());
    }
    println!(
        "enforcing  {}",
        count(
            started
                .iter()
                .filter(|action| matches!(action, supervisor::Action::Begin(_)))
                .count(),
            "project",
            "projects"
        )
    );
    println!("log        {}", supervisor.registry().log_path().display());
    for warning in &registration.warnings {
        eprintln!("ralon: warning: {warning}");
    }

    println!();
    println!("Install once → declare policy → enforcement starts automatically.");
    println!();
    println!("There is no third step. Write an {POLICY_FILE} in any project under those");
    println!("directories and it is enforced within a second, including projects cloned");
    println!("later. Delete the file and enforcement stops.");
    println!();
    println!("  ralon status     what is protected here, and whether it is");
    println!("  ralon pause      release this project to edit its policy");
    println!("  ralon uninstall  stop, and hand everything back");
    println!();
    if no_hooks {
        print_what_a_refusal_looks_like();
    } else {
        println!("An agent that reaches a protected path is told it is protected by Ralon,");
        println!("which file, and which pattern matched — the agent hook is installed in a");
        println!("project as it is enforced. Without it the agent sees only the filesystem's");
        println!("own error and has to guess. `--no-hooks` turns that off.");
    }
    if enforce::guard::BACKEND == Backend::Immutable {
        println!();
        print_macos_caveat();
    }
    report_uncovered_drives(&supervisor.registry().config);
    Ok(ExitCode::from(OK))
}

/// Names the drives no scope reaches, and how to cover them.
///
/// Windows only, and it exists because of one specific way this tool used to
/// fail people: the first-run default scope is the home directory, the home
/// directory is on `C:`, and a great many developers keep their repositories on
/// `D:` or `E:`. Those people wrote an `agent.lock`, watched nothing happen, and
/// had no reason to suspect that a scope was a concept.
///
/// Nothing here is scanned or assumed — the drives are listed and the command is
/// printed, and the developer decides.
fn report_uncovered_drives(config: &registry::Config) {
    // Compared as displayed, not as `Path`s. A canonical scope on Windows is
    // `\\?\C:\Users\me\code`, and `Path::starts_with` compares components — so
    // it does not start with `C:\`, and every drive read as uncovered including
    // the one the scopes are on. Caught by a test whose output listed a `C:`
    // scope and then advised covering `C:`.
    let covered: Vec<String> = config
        .roots
        .iter()
        .map(|root| registry::display(root))
        .collect();
    let uncovered: Vec<_> = supervisor::volumes::fixed_roots()
        .into_iter()
        .filter(|drive| {
            let drive = registry::display(drive);
            !covered.iter().any(|root| root.starts_with(&drive))
        })
        .collect();
    if uncovered.is_empty() {
        return;
    }

    println!();
    let drives = uncovered
        .iter()
        .map(|drive| registry::display(drive))
        .collect::<Vec<_>>()
        .join(", ");
    println!("No scope covers {drives} — an {POLICY_FILE} there is not enforced.");
    println!("If that is where you keep code:");
    println!(
        "  ralon scope add {}Projects",
        registry::display(&uncovered[0])
    );
}

/// Starts honouring `agent.lock` under a directory.
pub fn scope_add(directories: &[PathBuf]) -> Result<ExitCode> {
    let mut supervisor = Supervisor::load()?;

    for directory in canonical_directories(directories)? {
        match supervisor.add_scope(directory.clone()) {
            registry::ScopeChange::Added { replaced } => {
                println!("scope      {}", registry::display(&directory));
                for absorbed in replaced {
                    println!("  absorbed {}", registry::display(&absorbed));
                }
                warn_about_a_whole_drive(&directory);
            }
            registry::ScopeChange::AlreadyCovered { by } => {
                println!(
                    "already covered by {} — nothing to do",
                    registry::display(&by)
                );
            }
        }
    }
    supervisor.save_config()?;

    // Reconciled here rather than left to the supervisor's next pass, so that
    // when this command returns the projects under the new scope really are
    // enforced — and if one of them cannot be, it is said now, to the person
    // standing here, rather than into a log.
    let actions = supervisor.tick(true)?;
    let started = actions
        .iter()
        .filter(|action| matches!(action, supervisor::Action::Begin(_)))
        .count();
    println!("enforcing  {}", count(started, "project", "projects"));

    if !service::installed() {
        println!();
        println!("The supervisor is not installed, so nothing will pick up changes here");
        println!("automatically: `ralon install`.");
    }
    Ok(ExitCode::from(OK))
}

/// Stops honouring `agent.lock` under a directory, releasing what it held.
pub fn scope_remove(directories: &[PathBuf]) -> Result<ExitCode> {
    let mut supervisor = Supervisor::load()?;
    let mut removed = false;

    for directory in directories {
        // Canonicalized when it can be, so `d:\projects` matches the stored
        // `D:\Projects` — and falling back to the path as given, because a scope
        // on a drive that has since been unplugged still has to be removable.
        let canonical = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.clone());
        if supervisor.remove_scope(&canonical) {
            println!("dropped    {}", registry::display(&canonical));
            removed = true;
        } else {
            let covering = supervisor
                .registry()
                .config
                .covering(&canonical)
                .map(registry::display);
            match covering {
                Some(scope) => bail!(
                    "{} is not a scope — it is inside {scope}. Scopes are whole trees; \
                     remove {scope}, or leave it and let the policy files decide.",
                    registry::display(&canonical)
                ),
                None => bail!("{} is not a scope", registry::display(&canonical)),
            }
        }
    }
    supervisor.save_config()?;

    if removed {
        // The projects under a dropped scope are no longer discoverable, so
        // reconciliation sees them as gone and releases them. Done here so the
        // files are writable by the time this returns.
        let actions = supervisor.tick(true)?;
        let released = actions
            .iter()
            .filter(|action| matches!(action, supervisor::Action::End(_)))
            .count();
        println!("released   {}", count(released, "project", "projects"));
    }
    Ok(ExitCode::from(OK))
}

/// Shows the scopes and what is enforced in each.
pub fn scope_list() -> Result<ExitCode> {
    let supervisor = Supervisor::load()?;
    let registry = supervisor.registry();

    if registry.config.roots.is_empty() {
        println!("No scopes. Nothing will be enforced anywhere.");
        println!("  ralon scope add <DIR>");
        return Ok(ExitCode::from(OK));
    }

    for root in &registry.config.roots {
        let enforced = registry
            .workspaces
            .iter()
            .filter(|entry| entry.root.starts_with(root))
            .count();
        // A scope on a drive that is not currently mounted is not an error and
        // not a working scope either, and the difference is worth a word.
        let reachable = root.is_dir();
        println!(
            "{}  {}{}",
            registry::display(root),
            count(enforced, "project", "projects"),
            if reachable { "" } else { "  (unreachable)" }
        );
        for entry in &registry.workspaces {
            if entry.root.starts_with(root) {
                println!("  {}", registry::display(&entry.root));
            }
        }
    }

    report_uncovered_drives(&registry.config);
    Ok(ExitCode::from(OK))
}

/// A scope on a whole drive is legal and rarely meant.
fn warn_about_a_whole_drive(directory: &Path) {
    if directory.parent().is_some() {
        return;
    }
    eprintln!(
        "ralon: warning: {} is an entire drive. Discovery is bounded — it stops at \
         {} levels and skips dependency and system directories — but a directory \
         nearer your projects is faster and says more clearly what you meant.",
        registry::display(directory),
        registry::DEFAULT_MAX_DEPTH
    );
}

/// Undoes `install`, including everything it is currently holding.
pub fn uninstall(keep_enforcement: bool) -> Result<ExitCode> {
    let removed = service::uninstall()?;
    if removed {
        println!("deregistered the background supervisor");
    } else {
        println!("no background supervisor was registered");
    }

    if keep_enforcement {
        println!();
        println!("Enforcement was left in place. Nothing is watching it now, so a project");
        println!("stays protected exactly as it is — including after its {POLICY_FILE} is");
        println!("deleted. `ralon guard --stop` releases one project by hand.");
        return Ok(ExitCode::from(OK));
    }

    let mut supervisor = Supervisor::load()?;
    let released = supervisor.release_all()?;
    println!(
        "released   {}",
        count(released.len(), "project", "projects")
    );
    for root in &released {
        println!("  {}", registry::display(root));
    }
    Ok(ExitCode::from(OK))
}

/// Releases one project so its own policy can be edited.
pub fn pause(directory: &Path, minutes: u64, indefinitely: bool) -> Result<ExitCode> {
    let root = supervised_root(directory)?;
    let until = (!indefinitely).then(|| registry::now() + minutes * 60);

    let mut supervisor = Supervisor::load()?;
    supervisor.pause(&root, until)?;

    println!("paused     {}", registry::display(&root));
    match until {
        Some(_) => println!(
            "enforcement resumes on its own in {}",
            count(minutes as usize, "minute", "minutes")
        ),
        // Said plainly, because this is the state where a developer believes
        // they are protected and is not.
        None => println!("this project is NOT protected until `ralon resume`"),
    }
    Ok(ExitCode::from(OK))
}

pub fn resume(directory: &Path) -> Result<ExitCode> {
    let root = supervised_root(directory)?;
    let mut supervisor = Supervisor::load()?;
    supervisor.resume(&root)?;

    if enforce::guard::running(&root) {
        println!("enforcing  {}", registry::display(&root));
        Ok(ExitCode::from(OK))
    } else {
        // Never reported as resumed when it is not: this is the whole failure
        // mode the tool exists to prevent.
        bail!(
            "could not resume enforcement for {} — `ralon status` says what is wrong",
            root.display()
        )
    }
}

/// The supervisor itself.
pub fn daemon(foreground: bool, once: bool, home: Option<PathBuf>) -> Result<ExitCode> {
    if let Some(home) = home {
        registry::set_home(home);
    }
    if !service::SUPPORTED {
        bail!("{}", service::unsupported_reason());
    }

    let mut supervisor = Supervisor::load()?;

    if once {
        supervisor.verbose = true;
        let actions = supervisor.tick(true)?;
        if actions.is_empty() {
            println!("ralon: nothing to change");
        }
        return Ok(ExitCode::from(OK));
    }

    // `--foreground` is what launchd and Task Scheduler both want, and is what
    // happens either way: the alternative would be forking into the background,
    // which makes the service manager think the job died and restart it forever.
    let _ = foreground;
    supervisor::run(&mut supervisor)?;
    Ok(ExitCode::from(OK))
}

/// Canonical, existing directories, checked before anything is written.
///
/// Canonicalization is what makes the rest of the scope model work rather than
/// being a tidiness step. `covers()` compares components and is case-sensitive,
/// which is only correct because both sides have already been resolved to
/// whatever the filesystem calls them — so `d:\projects`, `D:\Projects\.`, and a
/// path reached through a junction all become one scope here, or they become
/// three scopes that do not recognise each other's repositories.
fn canonical_directories(requested: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut directories = Vec::new();
    for path in requested {
        let canonical = std::fs::canonicalize(path).with_context(|| {
            format!(
                "cannot use {} as a scope — no such directory",
                path.display()
            )
        })?;
        if !canonical.is_dir() {
            bail!(
                "cannot use {} as a scope — it is not a directory",
                path.display()
            );
        }
        if !directories.contains(&canonical) {
            directories.push(canonical);
        }
    }
    Ok(directories)
}

/// The project root for `pause` and `resume`, canonical so it matches what the
/// supervisor recorded.
fn supervised_root(directory: &Path) -> Result<PathBuf> {
    let policy = Policy::load(directory)?;
    Ok(std::fs::canonicalize(&policy.root)?)
}

/// The one thing a macOS user has to know that a Windows user does not.
fn print_macos_caveat() {
    println!("On macOS the supervisor enforces with `chflags uchg`, which refuses every");
    println!("ordinary write from every process — and which an agent can undo by running");
    println!("`chflags nouchg` itself. It is a narrowing, not a sandbox. `ralon run -- <agent>`");
    println!("applies a Seatbelt profile the agent cannot drop, and is strictly stronger.");
}

/// Holds the policy open with no command to supervise.
pub fn guard(directory: &Path, detach: bool, stop: bool, detached: bool) -> Result<ExitCode> {
    // Before anything that might print: this process has no console, and Rust
    // panics rather than shrugging when a write to one fails.
    if detached {
        enforce::guard::silence_standard_handles();
    }

    let policy = Policy::load(directory)?;
    let matcher = Matcher::new(&policy.patterns)?;
    let found = scan::scan(&policy.root, &matcher)?;
    let protected = scan::canonical_targets(&found)?;
    let root = std::fs::canonicalize(&policy.root)?;

    if stop {
        let stopped = enforce::guard::stop(&root)?;
        // Cleared whether or not one was running: a guard that was killed
        // rather than stopped leaves its ACL narrowing behind, and this is
        // where that gets tidied up.
        let cleared = enforce::guard::clear_leftovers(&protected);

        if stopped {
            println!("guard released — the protected paths are writable again");
        } else {
            println!("no guard was running for {}", registry::display(&root));
        }
        for directory in cleared {
            println!("cleared    {}", directory.display());
        }
        return Ok(ExitCode::from(OK));
    }

    if detach {
        enforce::guard::detach(&root)?;
        println!(
            "guard running in the background for {}",
            registry::display(&root)
        );
        println!("every process on this machine is now refused those paths");
        println!("stop it with: ralon guard --stop");

        // Said here as well as in the foreground path, which used to be the only
        // one that said it. A pattern matching nothing on disk protects nothing,
        // and `--detach` reporting a running guard and then falling silent about
        // it is the exact shape of failure this program exists to prevent — the
        // developer reads "every process is now refused those paths" and has no
        // way to learn that one of the paths was never among them.
        warn_about_unmatched(&policy, &found);
        warn_about_weaknesses(&policy, &found);

        println!();
        print_what_a_refusal_looks_like();
        return Ok(ExitCode::from(OK));
    }

    // A guard's backend is not `run`'s. `Backend::Auto` picks the strongest
    // thing that can be *inherited*, and a guard has no process to inherit it —
    // on macOS that is the difference between Seatbelt and `chflags`. Where no
    // guard is possible, resolution is skipped so `start` gets to explain why
    // rather than failing with the wrong message.
    let backend = if enforce::guard::AVAILABLE {
        enforce::resolve(enforce::guard::BACKEND)?
    } else {
        Backend::Auto
    };
    let plan = Plan::build(backend, &root, protected);
    let session = enforce::guard::start(&root, &plan)?;

    eprintln!(
        "ralon: {} locked, {} pinned, {} refusing new files",
        count(session.files(), "file", "files"),
        count(session.directories(), "directory", "directories"),
        count(session.refused_directories(), "directory", "directories"),
    );
    for warning in &session.warnings {
        eprintln!("ralon: warning: {warning}");
    }
    warn_about_unmatched(&policy, &found);
    warn_about_weaknesses(&policy, &found);
    eprintln!("ralon: guarding — Ctrl-C, or `ralon guard --stop`, to release");

    session.park()?;
    eprintln!("ralon: released");
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

    if enforce::guard::AVAILABLE {
        report_guard(&policy, &found);
    }
    report_supervisor(&policy);

    // "unavailable" states a fact and leaves the wrong conclusion available:
    // that a policy which lists protected paths is protecting them. It is not.
    if !availability.iter().any(|(_, status)| status.is_available()) {
        let hooked = [
            hook::claude::SETTINGS,
            hook::cursor::SETTINGS,
            hook::opencode::SETTINGS,
            hook::copilot::SETTINGS,
            hook::codex::SETTINGS,
            hook::gemini::SETTINGS,
            hook::antigravity::SETTINGS,
            hook::windsurf::SETTINGS,
            hook::cline::SETTINGS,
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
    println!("This is a courtesy layer: it covers an agent's own edit tools, not a");
    println!("shell command it runs, and an agent that can edit the config can remove");
    println!("it. Enforcement is `ralon run` — or `ralon guard` on Windows — which");
    println!("blocks processes, so it covers every agent, including the ones with no");
    println!("hooks at all.");
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
        // How they are pinned differs — a mount point, a held handle, a deny
        // rule — so the label says what it means rather than how it is done.
        for directory in &plan.pinned {
            println!("  no rename  {}", directory.display());
        }
    }

    if let Some(profile) = &plan.profile {
        // Printed in full, and printable on any machine: the profile is the
        // whole policy in the form the kernel will read it, so a reviewer can
        // check what will be denied without owning a Mac.
        println!("seatbelt   the profile that would be applied");
        for line in profile.lines() {
            println!("  {line}");
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

/// Whether a guard is holding this project, and whether a dead one left
/// anything behind.
///
/// Both halves matter. "A guard is running" is the only way to know the
/// protection is real without a wrapper command to point at, and a leftover
/// ACL is a directory that refuses new files with nothing running to explain
/// why — a mystery worth naming before someone spends an afternoon on it.
fn report_guard(policy: &Policy, found: &[ProtectedPath]) {
    let Ok(root) = std::fs::canonicalize(&policy.root) else {
        return;
    };

    if enforce::guard::running(&root) {
        println!("guard      running — every process on this machine is refused those paths");
    } else {
        println!("guard      not running (`ralon guard --detach`)");
    }

    let Ok(protected) = scan::canonical_targets(found) else {
        return;
    };
    let leftovers = enforce::guard::leftovers(&protected);
    if leftovers.is_empty() || enforce::guard::running(&root) {
        return;
    }
    println!();
    println!("These directories still refuse new files from a guard that was killed");
    println!("rather than stopped. That fails closed, which is the safe direction:");
    for directory in leftovers {
        println!("  {}", directory.display());
    }
    println!("  ralon guard --stop    clear it");
}

/// Whether this project is covered by the machine-wide supervisor, and whether
/// that supervisor is alive.
///
/// Three separate questions, reported separately, because two of them have a
/// comfortable answer that means nothing on its own. A project inside a watched
/// directory is *eligible* to be enforced; a registered service is *supposed* to
/// be running. Only the third — a supervisor process holding its claim right now
/// — says anything about whether the files are actually protected.
fn report_supervisor(policy: &Policy) {
    if !service::SUPPORTED {
        return;
    }
    let Ok(registry) = registry::Registry::load() else {
        return;
    };
    let root = std::fs::canonicalize(&policy.root).unwrap_or_else(|_| policy.root.clone());

    // Reported, then fallen through rather than returned from. A workspace can
    // be enforced by a supervisor nobody registered — `ralon daemon` run by
    // hand, or a machine part-way through being set up — and stopping here would
    // print "not installed" and say nothing at all about whether these files are
    // protected, which is the question being asked.
    match (service::installed(), single::running()) {
        (true, true) => println!("supervisor running"),
        (true, false) => {
            println!("supervisor registered, but no process is running — `ralon daemon --once`")
        }
        (false, true) => println!("supervisor running, but not registered to start at logon"),
        (false, false) => println!("supervisor not installed (`ralon install`)"),
    }

    println!("log        {}", registry.log_path().display());

    if !registry.config.covers(&root) {
        // The policy is here and it is doing nothing. That is the one state this
        // tool must never let look like protection, so it is said plainly and
        // followed by the command that fixes it — with a real parent directory
        // in it, not a placeholder.
        println!("workspace  policy found, but this project is outside every scope");
        println!("           it is NOT protected. To cover it:");
        println!(
            "             ralon scope add {}",
            registry::display(root.parent().unwrap_or(&root))
        );
        return;
    }

    match registry.find(&root).map(|entry| &entry.state) {
        Some(registry::State::Enforced) => println!("workspace  enforced by the supervisor"),
        Some(registry::State::Paused { until }) => match until {
            Some(until) => {
                let remaining = until.saturating_sub(registry::now()).div_ceil(60);
                println!(
                    "workspace  PAUSED — not protected. Resumes in {}.",
                    count(remaining as usize, "minute", "minutes")
                );
            }
            None => println!("workspace  PAUSED indefinitely — not protected (`ralon resume`)"),
        },
        Some(registry::State::Failed { reason }) => {
            println!("workspace  NOT protected — {reason}");
        }
        None => println!("workspace  in scope, not yet enforced (`ralon daemon --once`)"),
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
