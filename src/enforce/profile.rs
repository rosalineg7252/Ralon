//! The Seatbelt profile, as text.
//!
//! macOS is the one platform whose sandbox can say what the policy says. A
//! Landlock rule can only *grant*, so "everything except this file" has to be
//! reconstructed by granting every sibling along the way (`carve.rs`), and a
//! Windows handle can only refuse an open of something that already exists.
//! SBPL has `deny`, and takes it literally:
//!
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-write* (literal "/proj/.env") (subpath "/proj/config"))
//! ```
//!
//! That is the whole policy, in the shape it was written in. Nothing outside
//! the named paths behaves differently, and a protected directory covers what
//! is created inside it later — the gap the Windows backend has to reach for an
//! ACL to close.
//!
//! Generating the text is planning, not enforcement, so it lives here and is
//! tested everywhere. `run --dry-run --backend seatbelt` prints it on a Linux
//! CI runner exactly as it would be applied on a Mac, which is the only part of
//! this backend a machine without `sandbox_init` can check.

use std::path::{Path, PathBuf};

/// Whether a path is a directory. Injected so the builder is testable against
/// a tree that does not exist, the same way `carve` takes a directory lister.
pub type IsDirectory<'a> = dyn Fn(&Path) -> bool + 'a;

pub fn on_disk(path: &Path) -> bool {
    path.is_dir()
}

/// Builds the profile for `protected`, with `pinned` covering the directories
/// on the way to them.
///
/// Both halves are needed for the same reason the mount backend pins ancestor
/// directories: a rule names a *path*, and renaming a parent moves the file out
/// from under the path that was protected. Denying writes to the ancestor
/// *nodes* stops the rename without touching what is inside them — files can
/// still be created in `src/`, `src/` itself just cannot be moved or deleted.
pub fn build(protected: &[PathBuf], pinned: &[PathBuf], is_directory: &IsDirectory) -> String {
    let mut text = String::from(
        "(version 1)\n\n; Everything not named below behaves normally.\n(allow default)\n",
    );

    let rules: Vec<String> = protected
        .iter()
        .map(|path| {
            // A directory covers its whole subtree, including entries that do
            // not exist yet. A file is itself and nothing else.
            let form = if is_directory(path) {
                "subpath"
            } else {
                "literal"
            };
            format!("    ({form} \"{}\")", escape(path))
        })
        .collect();

    if !rules.is_empty() {
        text.push_str("\n; Declared in agent.lock.\n(deny file-write*\n");
        text.push_str(&rules.join("\n"));
        text.push_str("\n)\n");
    }

    let ancestors: Vec<String> = pinned
        .iter()
        .map(|path| format!("    (literal \"{}\")", escape(path)))
        .collect();

    if !ancestors.is_empty() {
        text.push_str(
            "\n; The directories leading to them: these deny the directory node\n\
             ; itself, so it cannot be renamed or removed, while leaving what is\n\
             ; inside it writable.\n(deny file-write*\n",
        );
        text.push_str(&ancestors.join("\n"));
        text.push_str("\n)\n");
    }

    text
}

/// SBPL strings are quoted, so a path containing a quote or a backslash has to
/// be escaped or it ends the string early — and a profile that fails to parse
/// is a profile that enforces nothing.
fn escape(path: &Path) -> String {
    let mut escaped = String::new();
    for character in path.to_string_lossy().chars() {
        if character == '"' || character == '\\' {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directories(names: &[&str]) -> impl Fn(&Path) -> bool {
        let names: Vec<PathBuf> = names.iter().map(PathBuf::from).collect();
        move |path: &Path| names.iter().any(|name| name == path)
    }

    #[test]
    fn a_file_is_literal_and_a_directory_is_a_subpath() {
        let text = build(
            &[PathBuf::from("/p/.env"), PathBuf::from("/p/config")],
            &[],
            &directories(&["/p/config"]),
        );

        assert!(text.contains("(literal \"/p/.env\")"), "{text}");
        assert!(text.contains("(subpath \"/p/config\")"), "{text}");
        assert!(text.contains("(deny file-write*"), "{text}");
    }

    #[test]
    fn everything_else_is_left_alone() {
        let text = build(&[PathBuf::from("/p/.env")], &[], &directories(&[]));
        assert!(text.contains("(allow default)"), "{text}");
    }

    #[test]
    fn ancestors_are_denied_as_nodes_not_as_subtrees() {
        let text = build(
            &[PathBuf::from("/p/src/index.tsx")],
            &[PathBuf::from("/p"), PathBuf::from("/p/src")],
            &directories(&["/p", "/p/src"]),
        );

        // A subpath here would make the whole project read-only, which is the
        // opposite of the point.
        assert!(text.contains("(literal \"/p/src\")"), "{text}");
        assert!(!text.contains("(subpath \"/p/src\")"), "{text}");
        assert!(!text.contains("(subpath \"/p\")"), "{text}");
    }

    #[test]
    fn a_quote_in_a_path_cannot_end_the_string_early() {
        let text = build(&[PathBuf::from("/p/we\"ird")], &[], &directories(&[]));
        assert!(text.contains(r#"(literal "/p/we\"ird")"#), "{text}");
    }

    #[test]
    fn a_policy_protecting_nothing_is_still_a_valid_profile() {
        let text = build(&[], &[], &directories(&[]));
        assert!(text.starts_with("(version 1)"), "{text}");
        assert!(!text.contains("deny"), "{text}");
    }
}
