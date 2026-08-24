//! Holding protected paths open so nothing else can write them.
//!
//! Windows resolves a conflict between two opens by the *share mode* the first
//! one asked for. A handle opened with only `FILE_SHARE_READ` lets everything
//! keep reading the file and makes every attempt to open it for writing,
//! deleting, or renaming fail with a sharing violation — for every process on
//! the machine, whatever it is and whoever started it.
//!
//! That is the property ACLs cannot give here. An agent runs as the same user
//! as Ralon, so any permission Ralon can set, the agent can unset; a handle is
//! not a permission and cannot be argued with. It also cleans itself up: when
//! this process ends, for any reason, the locks are gone. There is no state
//! left on disk to repair.

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Everything else may read; nobody may write, delete, or rename.
const FILE_SHARE_READ: u32 = 0x0000_0001;

/// Required to open a directory as a handle at all.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Open handles, held for as long as the sandboxed command runs. Dropping this
/// releases every one of them.
pub struct Locks {
    held: Vec<File>,
    pub files: usize,
    pub directories: usize,
}

/// Locks every protected path, and pins the directories leading to them.
///
/// `pinned` directories are opened too: a directory handle that does not share
/// deletion cannot be renamed or removed, which stops the path a policy names
/// from being moved out from under it — the same reason the Linux backend
/// turns those directories into mount points.
pub fn acquire(pinned: &[PathBuf], protected: &[PathBuf]) -> Result<Locks> {
    let mut locks = Locks {
        held: Vec::new(),
        files: 0,
        directories: 0,
    };

    for path in pinned {
        // A pin that cannot be taken is not fatal: the file locks below are
        // what protect the contents, and this only guards the path.
        if let Ok(handle) = directory(path) {
            locks.held.push(handle);
            locks.directories += 1;
        }
    }

    for path in protected {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        if metadata.is_dir() {
            locks.held.push(
                directory(path).with_context(|| format!("failed to lock {}", path.display()))?,
            );
            locks.directories += 1;
            // A directory handle stops the directory being renamed or removed,
            // but says nothing about the files inside it, so each one is locked
            // in its own right.
            for entry in walk(path) {
                if let Ok(handle) = file(&entry) {
                    locks.held.push(handle);
                    locks.files += 1;
                }
            }
        } else {
            locks.held.push(file(path).with_context(|| {
                format!(
                    "failed to lock {} — something already has it open for writing",
                    path.display()
                )
            })?);
            locks.files += 1;
        }
    }

    Ok(locks)
}

fn file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)?)
}

fn directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?)
}

/// Every file beneath `root`, symlinks not followed.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                found.push(entry.path());
            }
        }
    }

    found
}
