//! Turning a policy into an enforced sandbox.

pub mod carve;

#[cfg(target_os = "linux")]
pub mod linux;

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Backend {
    /// Pick the strongest backend the kernel supports.
    Auto,
    /// Read-only bind mounts in a locked mount namespace. Precise: only the
    /// protected paths change behaviour.
    Mount,
    /// Landlock LSM. Needs no namespaces, but cannot express "everything except
    /// this file", so directories leading to a protected path become
    /// create-restricted.
    Landlock,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Backend::Auto => "auto",
            Backend::Mount => "mount",
            Backend::Landlock => "landlock",
        };
        // pad, not write_str, so `{backend:<9}` lines up in tables
        f.pad(name)
    }
}

/// Whether a backend can be used right now, and why not.
// Off Linux nothing is ever available, which the dead code lint notices.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub enum Availability {
    Available { detail: String },
    Unavailable { reason: String },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Availability::Available { .. })
    }
}

impl fmt::Display for Availability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Availability::Available { detail } if detail.is_empty() => f.write_str("available"),
            Availability::Available { detail } => write!(f, "available ({detail})"),
            Availability::Unavailable { reason } => write!(f, "unavailable — {reason}"),
        }
    }
}

/// What `agent-lock run` will do, resolved against the current filesystem.
pub struct Plan {
    pub backend: Backend,
    /// Canonical paths that must not be modified.
    pub protected: Vec<PathBuf>,
    /// Mount only: directories to turn into mount points, parents first.
    pub pinned: Vec<PathBuf>,
    /// Landlock only: the carve-out derived from `protected`.
    pub carve: Option<carve::Carve>,
}

impl Plan {
    pub fn build(backend: Backend, root: &Path, protected: Vec<PathBuf>) -> Plan {
        let carve =
            (backend == Backend::Landlock).then(|| carve::plan(&protected, &carve::read_dir));
        let pinned = match backend {
            Backend::Mount => pinned_directories(root, &protected),
            _ => Vec::new(),
        };
        Plan {
            backend,
            protected,
            pinned,
            carve,
        }
    }
}

/// Directories between the project root and a protected path, root first.
///
/// A read-only bind mount protects a file's contents, but renaming its parent
/// directory moves the mount along with it and the path the policy named is
/// gone. Turning each parent into a mount point of its own closes that: the
/// kernel refuses to rename or remove a directory something is mounted on,
/// while leaving everything inside it writable.
pub fn pinned_directories(root: &Path, protected: &[PathBuf]) -> Vec<PathBuf> {
    let mut pinned = std::collections::BTreeSet::new();
    for path in protected {
        for ancestor in path.ancestors().skip(1) {
            if !ancestor.starts_with(root) {
                break;
            }
            pinned.insert(ancestor.to_path_buf());
            if ancestor == root {
                break;
            }
        }
    }
    // BTreeSet order is parent before child, which is the order they have to be
    // mounted in: a later bind of a parent would hide the mounts beneath it.
    pinned.into_iter().collect()
}

#[cfg(target_os = "linux")]
pub fn availability() -> Vec<(Backend, Availability)> {
    vec![
        (Backend::Mount, linux::mount_availability()),
        (Backend::Landlock, linux::landlock_availability()),
    ]
}

#[cfg(not(target_os = "linux"))]
pub fn availability() -> Vec<(Backend, Availability)> {
    let reason = format!(
        "kernel enforcement is Linux-only, this is {}",
        std::env::consts::OS
    );
    vec![
        (
            Backend::Mount,
            Availability::Unavailable {
                reason: reason.clone(),
            },
        ),
        (Backend::Landlock, Availability::Unavailable { reason }),
    ]
}

/// Resolves `Backend::Auto` against what the kernel actually offers.
pub fn resolve(requested: Backend) -> Result<Backend> {
    let availability = availability();
    let find = |backend: Backend| {
        availability
            .iter()
            .find(|(candidate, _)| *candidate == backend)
            .map(|(_, status)| status.clone())
            .expect("every backend is reported")
    };

    match requested {
        Backend::Auto => {
            // Mount first: it protects exactly what the policy names and leaves
            // everything else alone.
            for backend in [Backend::Mount, Backend::Landlock] {
                if find(backend).is_available() {
                    return Ok(backend);
                }
            }
            let reasons = availability
                .iter()
                .map(|(backend, status)| format!("\n  {backend:<9} {status}"))
                .collect::<String>();
            anyhow::bail!("no enforcement backend is available:{reasons}")
        }
        backend => match find(backend) {
            Availability::Available { .. } => Ok(backend),
            Availability::Unavailable { reason } => {
                anyhow::bail!("the {backend} backend is unavailable — {reason}")
            }
        },
    }
}

/// Applies `plan` to the current process, then replaces it with `command`.
///
/// Returns only on failure: on success the process image is gone.
#[cfg(target_os = "linux")]
pub fn enforce_and_exec(plan: &Plan, command: &[std::ffi::OsString]) -> anyhow::Error {
    linux::enforce_and_exec(plan, command)
}

#[cfg(not(target_os = "linux"))]
pub fn enforce_and_exec(_plan: &Plan, _command: &[std::ffi::OsString]) -> anyhow::Error {
    anyhow::anyhow!(
        "kernel enforcement is Linux-only, this is {} (use --dry-run to inspect the plan)",
        std::env::consts::OS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_every_directory_down_to_a_protected_file() {
        let root = Path::new("/p");
        let protected = vec![
            PathBuf::from("/p/src/deep/index.tsx"),
            PathBuf::from("/p/.env"),
        ];

        assert_eq!(
            pinned_directories(root, &protected),
            [
                PathBuf::from("/p"),
                PathBuf::from("/p/src"),
                PathBuf::from("/p/src/deep"),
            ]
        );
    }

    #[test]
    fn pinning_stops_at_the_project_root() {
        let root = Path::new("/p");
        let pinned = pinned_directories(root, &[PathBuf::from("/p/a")]);
        assert_eq!(pinned, [PathBuf::from("/p")]);
    }

    #[test]
    fn nothing_protected_means_nothing_pinned() {
        assert!(pinned_directories(Path::new("/p"), &[]).is_empty());
    }
}
