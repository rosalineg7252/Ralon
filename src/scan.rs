//! Resolves policy patterns against what is actually on disk.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

use crate::matcher::{relative_path, Matcher};

#[derive(Debug, Clone)]
pub struct ProtectedPath {
    /// Root-relative, `/` separated.
    pub relative: String,
    pub absolute: PathBuf,
    pub is_dir: bool,
    /// Policy pattern responsible for the match.
    pub pattern: String,
}

/// Walks the project and returns every existing path the policy protects.
///
/// A protected directory is returned once and not descended into: protecting a
/// directory protects everything beneath it, so listing the contents would add
/// nothing but noise (and thousands of entries for `node_modules`-shaped trees).
pub fn scan(root: &Path, matcher: &Matcher) -> Result<Vec<ProtectedPath>> {
    let mut found = Vec::new();
    let mut walker = WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    while let Some(entry) = walker.next() {
        let entry = match entry {
            Ok(entry) => entry,
            // An unreadable subtree cannot be protected by path rules anyway;
            // keep scanning rather than failing the whole command.
            Err(_) => continue,
        };

        let Some(relative) = relative_path(root, entry.path()) else {
            continue;
        };
        if !matcher.is_protected(&relative) {
            continue;
        }

        let is_dir = entry.file_type().is_dir();
        found.push(ProtectedPath {
            pattern: matcher
                .matched_pattern(&relative)
                .unwrap_or_default()
                .to_string(),
            relative,
            absolute: entry.path().to_path_buf(),
            is_dir,
        });
        if is_dir {
            walker.skip_current_dir();
        }
    }

    Ok(found)
}

/// Patterns that match nothing on disk. Enforcement can only protect paths that
/// exist, so these are worth surfacing.
pub fn unmatched_patterns(patterns: &[String], found: &[ProtectedPath]) -> Vec<String> {
    patterns
        .iter()
        .filter(|pattern| !found.iter().any(|path| &&path.pattern == pattern))
        .cloned()
        .collect()
}

/// Resolves symlinks so enforcement rules are attached to real paths.
pub fn canonical_targets(found: &[ProtectedPath]) -> Result<Vec<PathBuf>> {
    let mut targets = Vec::with_capacity(found.len());
    for path in found {
        let canonical = std::fs::canonicalize(&path.absolute)
            .with_context(|| format!("failed to resolve {}", path.absolute.display()))?;
        if !targets.contains(&canonical) {
            targets.push(canonical);
        }
    }
    Ok(targets)
}
