//! Landlock rule planning.
//!
//! Landlock rules are *additive*: a rule on a subdirectory can only grant more
//! access than its parents, never less. There is no way to say "everything is
//! writable except this file". The only way to deny a path is to never grant
//! its hierarchy, and instead grant every sibling along the way — walking from
//! `/` down to each protected path and handing out access to everything that
//! branches off. That carve-out is what this module computes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Carve {
    /// Directories on the path from `/` to a protected path. They receive no
    /// write rights, so entries cannot be created, deleted or renamed directly
    /// inside them.
    pub restricted: Vec<PathBuf>,
    /// Everything that branches off the restricted chain, granted full write
    /// access along with its whole subtree.
    pub granted: Vec<PathBuf>,
}

/// Computes the carve-out for `protected`.
///
/// `protected` must be absolute and symlink-free. `list_dir` returns the direct
/// children of a directory; it is injected so the planner can be tested without
/// touching a filesystem.
pub fn plan(protected: &[PathBuf], list_dir: &dyn Fn(&Path) -> Vec<PathBuf>) -> Carve {
    let protected: BTreeSet<&PathBuf> = protected.iter().collect();

    let mut restricted: BTreeSet<PathBuf> = BTreeSet::new();
    for path in &protected {
        for ancestor in path.ancestors().skip(1) {
            restricted.insert(ancestor.to_path_buf());
        }
    }

    let mut granted: BTreeSet<PathBuf> = BTreeSet::new();
    for directory in &restricted {
        for child in list_dir(directory) {
            // Ancestors of a protected path stay restricted, and protected
            // paths themselves are the point of the exercise.
            if restricted.contains(&child) || protected.contains(&child) {
                continue;
            }
            granted.insert(child);
        }
    }

    Carve {
        restricted: restricted.into_iter().collect(),
        granted: granted.into_iter().collect(),
    }
}

/// Lists real directory children, ignoring anything unreadable.
pub fn read_dir(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_fs(tree: &[(&'static str, &'static [&'static str])]) -> impl Fn(&Path) -> Vec<PathBuf> {
        let tree: Vec<(PathBuf, Vec<PathBuf>)> = tree
            .iter()
            .map(|(dir, children)| {
                let dir = PathBuf::from(dir);
                let children = children.iter().map(|c| dir.join(c)).collect();
                (dir, children)
            })
            .collect();
        move |path: &Path| {
            tree.iter()
                .find(|(dir, _)| dir == path)
                .map(|(_, children)| children.clone())
                .unwrap_or_default()
        }
    }

    #[test]
    fn grants_every_sibling_along_the_chain() {
        let list = fake_fs(&[
            ("/", &["home", "tmp", "usr"]),
            ("/home", &["dev"]),
            ("/home/dev", &["proj", "notes.txt"]),
            ("/home/dev/proj", &["src", "tests", "package.json"]),
            ("/home/dev/proj/src", &["index.tsx", "App.tsx"]),
        ]);
        let protected = vec![PathBuf::from("/home/dev/proj/src/index.tsx")];

        let carve = plan(&protected, &list);

        assert_eq!(
            carve.restricted,
            [
                PathBuf::from("/"),
                PathBuf::from("/home"),
                PathBuf::from("/home/dev"),
                PathBuf::from("/home/dev/proj"),
                PathBuf::from("/home/dev/proj/src"),
            ]
        );
        assert_eq!(
            carve.granted,
            [
                PathBuf::from("/home/dev/notes.txt"),
                PathBuf::from("/home/dev/proj/package.json"),
                PathBuf::from("/home/dev/proj/src/App.tsx"),
                PathBuf::from("/home/dev/proj/tests"),
                PathBuf::from("/tmp"),
                PathBuf::from("/usr"),
            ]
        );
    }

    #[test]
    fn protected_paths_are_never_granted() {
        let list = fake_fs(&[("/", &["p"]), ("/p", &["a", "b", "c"])]);
        let protected = vec![PathBuf::from("/p/a"), PathBuf::from("/p/c")];

        let carve = plan(&protected, &list);

        assert_eq!(carve.granted, [PathBuf::from("/p/b")]);
        assert_eq!(carve.restricted, [PathBuf::from("/"), PathBuf::from("/p")]);
    }

    #[test]
    fn a_protected_directory_is_not_descended_into() {
        let list = fake_fs(&[
            ("/", &["p"]),
            ("/p", &["config", "src"]),
            ("/p/config", &["db.yaml"]),
        ]);
        let protected = vec![PathBuf::from("/p/config")];

        let carve = plan(&protected, &list);

        assert!(!carve.restricted.contains(&PathBuf::from("/p/config")));
        assert_eq!(carve.granted, [PathBuf::from("/p/src")]);
    }

    #[test]
    fn no_protected_paths_means_nothing_to_plan() {
        let list = fake_fs(&[("/", &["p"])]);
        assert_eq!(plan(&[], &list), Carve::default());
    }
}
