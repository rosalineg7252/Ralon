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

/// The scopes, as a person edits them. Public because the running supervisor
/// watches for it by name: a `ralon scope add` in another terminal writes this
/// file, and that write is how the daemon finds out.
pub const CONFIG_FILE: &str = "config.yaml";
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
    // Version control and dependency trees. `.git` alone is thousands of
    // directories per repository.
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
    // Platform directories that hold no projects and a great many entries.
    // `Library` is macOS; the rest are Windows, and `AppData` is the one that
    // matters — the default scope is the home directory, and on Windows most of
    // what is under a home directory by count lives in `AppData`. Sweeping it
    // cost more than everything else put together and could not find anything.
    "Library",
    "AppData",
    "Application Data",
    "$Recycle.Bin",
    "System Volume Information",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
];

/// What adding a scope did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeChange {
    /// Now a scope. `replaced` are the narrower ones it absorbed.
    Added { replaced: Vec<PathBuf> },
    /// Already inside `by`, so adding it would change nothing.
    AlreadyCovered { by: PathBuf },
}

/// The part a person edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Directories the developer's projects live in.
    pub roots: Vec<PathBuf>,
    #[serde(default = "default_depth")]
    pub max_depth: usize,
    /// Whether an enforced project also gets the agent hook.
    ///
    /// On by default, and it is the difference between an agent being told
    /// "protected by Ralon" and being handed `EBUSY: resource busy or locked` to
    /// interpret. Enforcement does not depend on it either way.
    #[serde(default = "default_hooks")]
    pub hooks: bool,
}

fn default_depth() -> usize {
    DEFAULT_MAX_DEPTH
}

fn default_hooks() -> bool {
    true
}

impl Default for Config {
    fn default() -> Config {
        Config {
            roots: Vec::new(),
            max_depth: DEFAULT_MAX_DEPTH,
            hooks: true,
        }
    }
}

impl Config {
    /// Whether `path` lies inside a declared scope.
    ///
    /// Checked on every candidate, including the ones a filesystem notification
    /// reports, so an event about a directory nobody declared cannot smuggle a
    /// workspace in behind the configuration.
    ///
    /// `starts_with` compares whole components, so `D:\Projects` does not cover
    /// `D:\Projects-old`, and it is case-sensitive — which is correct only
    /// because both sides are canonical by construction. Scopes are canonicalized
    /// when added and workspaces when discovered, so `d:\projects` and
    /// `D:\Projects` have both already become whatever the filesystem calls it.
    pub fn covers(&self, path: &Path) -> bool {
        self.roots.iter().any(|root| path.starts_with(root))
    }

    /// The scope covering `path`, if any.
    pub fn covering(&self, path: &Path) -> Option<&Path> {
        self.roots
            .iter()
            .find(|root| path.starts_with(root))
            .map(PathBuf::as_path)
    }

    /// Adds a canonical directory as a scope, folding it against the rest.
    ///
    /// Scopes are kept as a set of disjoint trees, and this is where that is
    /// enforced. Two overlapping scopes would mean the sweep walking the same
    /// subtree twice and two filesystem watchers reporting the same events —
    /// harmless, since reconciliation is idempotent, and pure waste. More to the
    /// point, "you already have this" and "this replaces three narrower ones"
    /// are things a person adding a scope wants to be told rather than left to
    /// deduce from `scope list`.
    ///
    /// Pure: the caller canonicalizes, so the folding rules are testable without
    /// a filesystem.
    pub fn add(&mut self, canonical: PathBuf) -> ScopeChange {
        if let Some(existing) = self.covering(&canonical) {
            return ScopeChange::AlreadyCovered {
                by: existing.to_path_buf(),
            };
        }

        // Nothing covers it, so it may cover others. A broader scope absorbing
        // narrower ones keeps the set disjoint without asking.
        let replaced: Vec<PathBuf> = self
            .roots
            .iter()
            .filter(|root| root.starts_with(&canonical))
            .cloned()
            .collect();
        self.roots.retain(|root| !root.starts_with(&canonical));
        self.roots.push(canonical);
        self.roots.sort();

        ScopeChange::Added { replaced }
    }

    /// Drops a scope. `false` means it was not one.
    ///
    /// Only an exact match: removing `D:\Projects\app` when the scope is
    /// `D:\Projects` would have to either do nothing or silently carve a hole in
    /// a tree, and a hole is not something this configuration can express.
    pub fn remove(&mut self, canonical: &Path) -> bool {
        let before = self.roots.len();
        self.roots.retain(|root| root != canonical);
        self.roots.len() != before
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

/// `2026-08-26 09:14:11Z`, for the log.
///
/// Hand-rolled rather than pulled in with a date crate. The whole point of this
/// program is that it has no runtime dependencies, and a log line is not worth
/// the first one — while `1787762051` in a file a developer opens when something
/// has gone wrong is worth rather less than nothing.
///
/// UTC, with the `Z` said out loud. A supervisor's log is read next to an
/// agent's transcript and a shell's history, and a local time with no offset is
/// the one format that cannot be lined up against either.
pub fn timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let time = seconds % 86_400;

    // Howard Hinnant's civil-from-days, which is exact for any date and short
    // enough to check by eye. Shifts the epoch to 0000-03-01 so leap days land
    // at the end of the cycle and the month arithmetic has no special cases.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;

    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = if march_month < 10 {
        march_month + 3
    } else {
        march_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_outside_every_root_is_not_a_workspace() {
        let config = Config {
            roots: vec![PathBuf::from("/home/dev/code")],
            max_depth: DEFAULT_MAX_DEPTH,
            hooks: true,
        };
        assert!(config.covers(Path::new("/home/dev/code/app")));
        assert!(!config.covers(Path::new("/tmp/downloaded/app")));
    }

    #[test]
    fn no_roots_covers_nothing() {
        assert!(!Config::default().covers(Path::new("/anywhere")));
    }

    /// Three unrelated places a developer might keep code, spelled the way the
    /// running platform spells them.
    ///
    /// On Windows these are separate *drives*, which is where the scope model
    /// actually hurt: the first-run default is the home directory on `C:`, and a
    /// great many developers keep their repositories on `D:` or `E:`. There is no
    /// Unix equivalent of a drive letter — `Path` there reads `C:\Users\me` as a
    /// single component with no separator in it — so the same rules are checked
    /// against separate mount points instead. Both are "roots that share no
    /// prefix", which is the property every assertion below actually depends on.
    #[cfg(windows)]
    const HOME: &str = r"C:\Users\me\Projects";
    #[cfg(windows)]
    const SECOND: &str = r"D:\Projects";
    #[cfg(windows)]
    const THIRD: &str = r"E:\Work";
    #[cfg(windows)]
    const UNRELATED: &str = r"F:\Elsewhere";

    #[cfg(not(windows))]
    const HOME: &str = "/home/me/Projects";
    #[cfg(not(windows))]
    const SECOND: &str = "/mnt/data/Projects";
    #[cfg(not(windows))]
    const THIRD: &str = "/media/work";
    #[cfg(not(windows))]
    const UNRELATED: &str = "/srv/elsewhere";

    fn under(root: &str, child: &str) -> PathBuf {
        Path::new(root).join(child)
    }

    fn scoped(roots: &[&str]) -> Config {
        let mut config = Config::default();
        for root in roots {
            config.add(PathBuf::from(root));
        }
        config
    }

    #[test]
    fn scopes_on_separate_roots_are_all_covered() {
        let config = scoped(&[HOME, SECOND, THIRD]);

        assert!(config.covers(&under(HOME, "app")));
        assert!(config.covers(&under(SECOND, "app")));
        assert!(config.covers(&under(THIRD, "client/app")));
        // A root with no scope on it is not covered by a scope on another.
        assert!(!config.covers(&under(UNRELATED, "app")));
    }

    #[test]
    fn where_ralon_is_installed_does_not_decide_what_is_covered() {
        // The whole complaint: a home directory on C: must not be the reason a
        // repository on D: goes unprotected.
        let config = scoped(&[SECOND]);
        assert!(config.covers(&under(SECOND, "app")));
        assert!(!config.covers(&under(HOME, "app")));
    }

    #[test]
    fn a_scope_inside_a_scope_is_not_added_twice() {
        let mut config = scoped(&[SECOND]);
        assert_eq!(
            config.add(under(SECOND, "client")),
            ScopeChange::AlreadyCovered {
                by: PathBuf::from(SECOND)
            }
        );
        assert_eq!(config.roots, [PathBuf::from(SECOND)]);
    }

    #[test]
    fn the_same_scope_added_twice_changes_nothing() {
        let mut config = scoped(&[SECOND]);
        assert!(matches!(
            config.add(PathBuf::from(SECOND)),
            ScopeChange::AlreadyCovered { .. }
        ));
        assert_eq!(config.roots.len(), 1);
    }

    #[test]
    fn a_broader_scope_absorbs_the_narrower_ones() {
        let mut config = Config::default();
        config.add(under(SECOND, "one"));
        config.add(under(SECOND, "two"));
        config.add(PathBuf::from(THIRD));

        let change = config.add(PathBuf::from(SECOND));
        assert_eq!(
            change,
            ScopeChange::Added {
                replaced: vec![under(SECOND, "one"), under(SECOND, "two")]
            }
        );
        // The unrelated scope survives; the set is left disjoint.
        assert_eq!(
            config.roots,
            [PathBuf::from(SECOND), PathBuf::from(THIRD)]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_covered() {
        // `starts_with` compares components, not characters. If it did not,
        // `D:\Projects` would swallow `D:\Projects-old` and the developer would
        // have a scope they never asked for.
        let config = scoped(&[SECOND]);
        assert!(!config.covers(Path::new(&format!("{SECOND}-old"))));
    }

    #[test]
    fn removing_a_scope_takes_only_that_one() {
        let mut config = scoped(&[SECOND, THIRD]);
        assert!(config.remove(Path::new(SECOND)));
        assert_eq!(config.roots, [PathBuf::from(THIRD)]);
        assert!(!config.remove(Path::new(SECOND)));
    }

    #[test]
    fn removing_something_that_is_not_a_scope_says_so() {
        let mut config = scoped(&[SECOND]);
        // Inside a scope, but not a scope. Removing it would have to carve a
        // hole this configuration cannot express, so it does nothing and the
        // caller reports that rather than pretending.
        assert!(!config.remove(&under(SECOND, "app")));
        assert_eq!(config.roots, [PathBuf::from(SECOND)]);
    }

    #[test]
    fn timestamps_are_readable_and_correct() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00Z");
        // A leap day, and the day after it, in a century year that *is* a leap
        // year — the case the naive `% 4` version gets wrong.
        assert_eq!(timestamp(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(timestamp(951_868_800), "2000-03-01 00:00:00Z");
        // A century year that is not.
        assert_eq!(timestamp(4_107_542_400), "2100-03-01 00:00:00Z");
        // UTC, not local. 20691 whole days past the epoch leaves 59651 seconds,
        // which is 16:34:11 — worth spelling out, because the first version of
        // this assertion read the local clock off the machine it was written on
        // and expected 18:34.
        assert_eq!(timestamp(1_787_762_051), "2026-08-26 16:34:11Z");
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
