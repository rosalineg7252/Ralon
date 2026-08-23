//! Turns policy patterns into path matching.

use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::path::Path;

/// Linux is the platform Agent Lock enforces on, and there path comparison is
/// case sensitive. On case-insensitive filesystems we match case-insensitively:
/// for a deny list, matching more than asked is the safe direction.
const CASE_INSENSITIVE: bool = cfg!(any(target_os = "windows", target_os = "macos"));

pub struct Matcher {
    set: GlobSet,
    /// Pattern owning each glob in `set`, by glob index.
    owners: Vec<usize>,
    patterns: Vec<String>,
}

impl Matcher {
    pub fn new(patterns: &[String]) -> Result<Matcher> {
        let mut builder = GlobSetBuilder::new();
        let mut owners = Vec::new();

        for (index, pattern) in patterns.iter().enumerate() {
            for glob in expand(pattern) {
                let compiled = GlobBuilder::new(&glob)
                    .literal_separator(true)
                    .case_insensitive(CASE_INSENSITIVE)
                    .build()
                    .with_context(|| format!("invalid pattern `{pattern}`"))?;
                builder.add(compiled);
                owners.push(index);
            }
        }

        Ok(Matcher {
            set: builder.build()?,
            owners,
            patterns: patterns.to_vec(),
        })
    }

    /// `path` must be relative to the project root, using `/` separators.
    pub fn is_protected(&self, path: &str) -> bool {
        self.set.is_match(path)
    }

    /// The first policy pattern that protects `path`, for reporting.
    pub fn matched_pattern(&self, path: &str) -> Option<&str> {
        let mut matches = self.set.matches(path);
        matches.sort_unstable();
        matches
            .first()
            .map(|glob| self.patterns[self.owners[*glob]].as_str())
    }
}

/// A pattern naming a directory protects the directory *and* its contents, so
/// each pattern becomes up to two globs.
fn expand(pattern: &str) -> Vec<String> {
    if let Some(base) = pattern.strip_suffix("/**") {
        // `config/**` must also cover `config` itself, otherwise the directory
        // could be renamed out from under the policy.
        vec![base.to_string(), pattern.to_string()]
    } else if pattern.ends_with('*') {
        // Wildcards elsewhere (`**`, `src/*.ts`) match exactly what they say.
        vec![pattern.to_string()]
    } else {
        vec![pattern.to_string(), format!("{pattern}/**")]
    }
}

/// Renders a path relative to `root` as a `/`-separated string.
pub fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut out = String::new();
    for component in relative.components() {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&component.as_os_str().to_string_lossy());
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(patterns: &[&str]) -> Matcher {
        let owned: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
        Matcher::new(&owned).unwrap()
    }

    #[test]
    fn matches_exact_files() {
        let m = matcher(&["src/index.tsx", ".env"]);
        assert!(m.is_protected("src/index.tsx"));
        assert!(m.is_protected(".env"));
        assert!(!m.is_protected("src/App.tsx"));
        assert!(!m.is_protected("index.tsx"));
        assert!(!m.is_protected("other/src/index.tsx"));
    }

    #[test]
    fn a_directory_covers_its_contents() {
        let m = matcher(&["config"]);
        assert!(m.is_protected("config"));
        assert!(m.is_protected("config/db.yaml"));
        assert!(m.is_protected("config/nested/deep.yaml"));
        assert!(!m.is_protected("configuration"));
        assert!(!m.is_protected("src/config"));
    }

    #[test]
    fn double_star_covers_the_directory_itself() {
        let m = matcher(&[".github/workflows/**"]);
        assert!(m.is_protected(".github/workflows"));
        assert!(m.is_protected(".github/workflows/ci.yml"));
        assert!(!m.is_protected(".github"));
        assert!(!m.is_protected(".github/dependabot.yml"));
    }

    #[test]
    fn single_star_does_not_cross_separators() {
        let m = matcher(&["src/*.ts"]);
        assert!(m.is_protected("src/auth.ts"));
        assert!(!m.is_protected("src/deep/auth.ts"));
    }

    #[test]
    fn double_star_crosses_separators() {
        let m = matcher(&["**/secrets.json"]);
        assert!(m.is_protected("secrets.json"));
        assert!(m.is_protected("a/b/secrets.json"));
    }

    #[test]
    fn reports_the_pattern_that_matched() {
        let m = matcher(&["agent.lock", "config/**"]);
        assert_eq!(m.matched_pattern("config/db.yaml"), Some("config/**"));
        assert_eq!(m.matched_pattern("agent.lock"), Some("agent.lock"));
        assert_eq!(m.matched_pattern("src/App.tsx"), None);
    }

    #[test]
    fn relative_paths_use_forward_slashes() {
        let root = Path::new("/p");
        assert_eq!(
            relative_path(root, Path::new("/p/src/index.tsx")).as_deref(),
            Some("src/index.tsx")
        );
        assert_eq!(relative_path(root, Path::new("/p")), None);
        assert_eq!(relative_path(root, Path::new("/other/x")), None);
    }
}
