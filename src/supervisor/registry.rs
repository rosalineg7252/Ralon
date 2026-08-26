//! What the supervisor is allowed to look at, and what it remembers doing.
//!
//! Two files, and the split between them is the point.
//!
//! `config.yaml` is written by `ralon install` and edited by a person. It lists
//! the directories the supervisor may search for `agent.lock` in. Nothing
//! outside them is a workspace, however many policy files it contains — which is
//! the answer to "what stops an `agent.lock` inside a downloaded tarball from
//! locking files on my machine". A policy declares *which paths in its own
//! project* are off limits; being found is a privilege the developer grants once,
//! to a directory, by name.
//!
//! `workspaces.json` is written by the supervisor and read by nobody else. It
//! exists for one reason: a supervisor that starts after a crash has to undo what
//! the previous one applied, and by then `agent.lock` may be gone, so the paths
//! cannot be recomputed from the policy. They are remembered instead.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::policy::POLICY_FILE;

/// Relocates everything below. Tests set it; so can anyone who would rather the
/// supervisor kept its state somewhere other than the platform default.
pub const HOME_VAR: &str = "RALON_HOME";

const CONFIG_FILE: &str = "config.yaml";
const WORKSPACES_FILE: &str = "workspaces.json";

/// How deep below a scan root an `agent.lock` will be noticed.
///
/// A repository is normally two or three levels under wherever the developer
/// keeps code. The limit is not a performance tweak so much as a statement of
/// intent: the supervisor searches for projects, not for every file on the disk.
pub const DEFAULT_MAX_DEPTH: usize = 8;

/// Directories the sweep does not descend into.
///
/// Dependency and build trees hold no projects and are the overwhelming majority
/// of the directories under a code root; `.git` alone is thousands of entries per
/// repository. Skipping them is what keeps a full sweep cheap enough to run as a
/// backstop behind the real watcher.
pub const SKIPPED: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
    ".gradle",
    "Pods",
    "DerivedData",
    "Library",
];

/// The part a person edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Where to look for `agent.lock`.
    pub roots: Vec<PathBuf>,
    #[serde(default = "default_depth")]
    pub max_depth: usize,
}

fn default_depth() -> usize {
    DEFAULT_MAX_DEPTH
}

impl Default for Config {
    fn default() -> Config {
        Config {
            roots: Vec::new(),
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl Config {
    /// Whether `path` lies inside a registered scan root.
    ///
    /// Checked on every candidate, including the ones a watcher reports, so a
    /// notification about a directory nobody registered cannot smuggle a
    /// workspace in behind the configuration.
    pub fn covers(&self, path: &Path) -> bool {
        self.roots.iter().any(|root| path.starts_with(root))
    }
}

/// What the supervisor did to a workspace, and is therefore on the hook for
/// undoing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum State {
    /// Enforcement is in place.
    Enforced,
    /// Deliberately released so the developer can edit the policy.
    ///
    /// `until` is a unix timestamp. `None` means until somebody says otherwise,
    /// which is the option you have to ask for: a pause that is forgotten about
    /// is a project that stopped being protected without anyone deciding it
    /// should, so the default expires.
    Paused { until: Option<u64> },
    /// There is an `agent.lock` here that could not be turned into enforcement.
    /// Kept so the reason can be reported instead of being retried in silence.
    Failed { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub root: PathBuf,
    #[serde(flatten)]
    pub state: State,
    /// Canonical paths enforcement was actually applied to.
    ///
    /// Not derived from the policy on demand, because the case this exists for
    /// is the one where the policy is gone.
    #[serde(default)]
    pub applied: Vec<PathBuf>,
}

/// Config plus memory, loaded from one directory.
pub struct Registry {
    home: PathBuf,
    pub config: Config,
    pub workspaces: Vec<Workspace>,
}

impl Registry {
    /// Loads what is there. Missing files are empty ones, not errors: the first
    /// run of the supervisor has neither.
    pub fn load() -> Result<Registry> {
        let home = home()?;
        Ok(Registry {
            config: read_config(&home)?,
            workspaces: read_workspaces(&home),
            home,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn config_path(&self) -> PathBuf {
        self.home.join(CONFIG_FILE)
    }

    pub fn log_path(&self) -> PathBuf {
        self.home.join("supervisor.log")
    }

    pub fn find(&self, root: &Path) -> Option<&Workspace> {
        self.workspaces.iter().find(|entry| entry.root == root)
    }

    /// Records what a workspace is now, replacing whatever it was.
    pub fn set(&mut self, root: &Path, state: State, applied: Vec<PathBuf>) {
        let entry = Workspace {
            root: root.to_path_buf(),
            state,
            applied,
        };
        match self
            .workspaces
            .iter_mut()
            .find(|existing| existing.root == root)
        {
            Some(existing) => *existing = entry,
            None => self.workspaces.push(entry),
        }
    }

    pub fn forget(&mut self, root: &Path) {
        self.workspaces.retain(|entry| entry.root != root);
    }

    pub fn save_config(&self) -> Result<()> {
        std::fs::create_dir_all(&self.home)
            .with_context(|| format!("failed to create {}", self.home.display()))?;
        let text = serde_yaml_ng::to_string(&self.config)?;
        write_atomically(&self.config_path(), text.as_bytes())
    }

    pub fn save_workspaces(&self) -> Result<()> {
        std::fs::create_dir_all(&self.home)
            .with_context(|| format!("failed to create {}", self.home.display()))?;
        let text = serde_json::to_string_pretty(&self.workspaces)?;
        write_atomically(&self.home.join(WORKSPACES_FILE), text.as_bytes())
    }
}

/// Set once at startup by `--home`, which is how a registered service is told
/// where its state lives.
///
/// An argument rather than the environment, because a service does not inherit
/// the environment of the shell that installed it — it inherits launchd's or
/// Task Scheduler's. A `RALON_HOME` exported in a terminal would apply to
/// `ralon install` and not to the daemon it registered, and the two would look
/// after different sets of workspaces without either of them noticing.
static OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub fn set_home(path: PathBuf) {
    let _ = OVERRIDE.set(path);
}

/// Where the supervisor keeps its state.
pub fn home() -> Result<PathBuf> {
    if let Some(explicit) = OVERRIDE.get() {
        return Ok(explicit.clone());
    }
    if let Some(override_path) = std::env::var_os(HOME_VAR) {
        return Ok(PathBuf::from(override_path));
    }

    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|path| path.join("Ralon"));

    #[cfg(target_os = "macos")]
    let base = user_home().map(|home| home.join("Library/Application Support/Ralon"));

    #[cfg(not(any(windows, target_os = "macos")))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| user_home().map(|home| home.join(".local/state")))
        .map(|path| path.join("ralon"));

    base.with_context(|| {
        format!("could not work out where to keep Ralon's state — set {HOME_VAR} to a directory")
    })
}

/// The user's home directory, without a crate to ask.
pub fn user_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn read_config(home: &Path) -> Result<Config> {
    let path = home.join(CONFIG_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Config::default());
    };
    // A broken config is fatal rather than defaulted. Defaulting means an empty
    // root list, which means the supervisor finds no workspaces and protects
    // nothing — the failure this project refuses to have happen quietly.
    serde_yaml_ng::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

/// Unparseable memory reads as no memory.
///
/// The opposite of the config: this file is Ralon's own and a person never sees
/// it, so a corrupt one is a bug rather than a misconfiguration, and refusing to
/// start over it would leave a machine with no supervisor until somebody deleted
/// a file they have never heard of. Losing it costs one stale workspace's
/// cleanup, which the next `ralon status` reports as a leftover.
fn read_workspaces(home: &Path) -> Vec<Workspace> {
    std::fs::read_to_string(home.join(WORKSPACES_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Writes through a temporary file so a supervisor killed mid-write leaves the
/// previous state rather than half of the new one.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed to replace {}", path.display()))
}

/// Every directory under `roots` that holds an `agent.lock`.
///
/// The backstop behind the platform watcher, and the whole story on the first
/// tick after start-up, when there is no watcher history to replay.
pub fn sweep(config: &Config) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    for root in &config.roots {
        sweep_into(root, config.max_depth, &mut found);
    }
    found
}

fn sweep_into(directory: &Path, remaining: usize, found: &mut BTreeSet<PathBuf>) {
    if directory.join(POLICY_FILE).is_file() {
        // A project is a leaf: `agent.lock` governs everything beneath it, so a
        // nested one would be a second policy over paths the first already
        // covers, and enforcing both means two sessions fighting over the same
        // files.
        //
        // Canonical, and this is load-bearing rather than tidy. A project is
        // identified to the enforcement layer by a hash of its path — the
        // Windows guard's claim is a named kernel object — so two spellings of
        // one directory are two projects that do not know about each other, and
        // the supervisor decides a guard is not running while it is. Reached by
        // walking, via a symlink, through a drive substitution, spelled in a
        // different case: all the same project only if they are resolved here.
        found.insert(std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf()));
        return;
    }
    if remaining == 0 {
        return;
    }

    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        // `file_type` rather than `path().is_dir()`: the latter follows
        // symlinks, and a link pointing back up the tree turns the sweep into a
        // loop the depth limit only ends eventually.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name != ".config" || SKIPPED.contains(&name.as_ref()) {
            continue;
        }
        sweep_into(&entry.path(), remaining - 1, found);
    }
}

/// A path in the spelling a person expects to see.
///
/// Workspaces are identified by their canonical path, which on Windows means the
/// verbatim form — `\\?\C:\code\app`. That is the right thing to *store*: it is
/// the only spelling that is the same for every process, and the Windows guard's
/// claim is a hash of it, so a supervisor and a guard that disagreed about the
/// prefix would disagree about which project they were talking about. It is the
/// wrong thing to *print*: `\\?\` in front of every path in every message reads
/// like a bug, and it is not a path anyone can paste into `cmd`.
pub fn display(path: &Path) -> String {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        // `\\?\UNC\server\share` is not a path with a prefix to remove; taking
        // it off leaves `UNC\server\share`, which names nothing.
        Some(rest) if !rest.starts_with("UNC\\") => rest.to_string(),
        _ => text,
    }
}

/// Seconds since the epoch. Used for pause expiry, where a clock that goes
/// backwards costs an early re-enforcement, which is the harmless direction.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_outside_every_root_is_not_a_workspace() {
        let config = Config {
            roots: vec![PathBuf::from("/home/dev/code")],
            max_depth: DEFAULT_MAX_DEPTH,
        };
        assert!(config.covers(Path::new("/home/dev/code/app")));
        assert!(!config.covers(Path::new("/tmp/downloaded/app")));
    }

    #[test]
    fn no_roots_covers_nothing() {
        assert!(!Config::default().covers(Path::new("/anywhere")));
    }

    #[test]
    fn state_round_trips_through_json() {
        let entry = Workspace {
            root: PathBuf::from("/p"),
            state: State::Paused { until: Some(42) },
            applied: vec![PathBuf::from("/p/.env")],
        };
        let text = serde_json::to_string(&entry).unwrap();
        let back: Workspace = serde_json::from_str(&text).unwrap();
        assert_eq!(back.state, State::Paused { until: Some(42) });
        assert_eq!(back.applied, [PathBuf::from("/p/.env")]);
    }
}
