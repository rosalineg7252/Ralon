//! Parsing and validation of `agent.lock`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Name of the policy file. Looked up from the working directory upwards.
pub const POLICY_FILE: &str = "agent.lock";

/// The only policy version this build understands.
pub const CURRENT_VERSION: u32 = 1;

/// Written by `ralon init`.
pub const TEMPLATE: &str = "\
protect:
  - file
  - folder
";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    /// Optional, and absent means 1.
    ///
    /// It was required, and it earned nothing. The field exists so that a
    /// future format change can be told apart from this one — but "no version
    /// stated" is a perfectly good way to say *version 1*, and it is a rule that
    /// stays true forever, so requiring it bought a line of ceremony in every
    /// policy file and no information.
    ///
    /// Dropping the requirement is safe here specifically because it is not what
    /// validates the file. `deny_unknown_fields` is: a policy with a typo
    /// (`protects:`) or one that is some other kind of YAML entirely is still
    /// rejected, rather than parsing as a policy that happens to protect
    /// nothing. That distinction is the whole risk in this change, and it is
    /// covered by tests below rather than by argument.
    #[serde(default = "assume_current_version")]
    version: u32,
    #[serde(default)]
    protect: Vec<String>,
}

fn assume_current_version() -> u32 {
    CURRENT_VERSION
}

/// A parsed, validated policy plus the project root it applies to.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Directory containing `agent.lock`. All patterns are relative to it.
    pub root: PathBuf,
    /// Absolute path of the policy file itself.
    pub file: PathBuf,
    pub version: u32,
    /// Normalized patterns, `agent.lock` first.
    pub patterns: Vec<String>,
}

impl Policy {
    /// Walks up from `start` looking for `agent.lock`.
    pub fn find_root(start: &Path) -> Option<PathBuf> {
        let start = absolute(start).ok()?;
        start
            .ancestors()
            .find(|dir| dir.join(POLICY_FILE).is_file())
            .map(Path::to_path_buf)
    }

    /// Loads the policy governing `start`.
    pub fn load(start: &Path) -> Result<Policy> {
        let root = Policy::find_root(start).with_context(|| {
            format!(
                "no {POLICY_FILE} found in {} or any parent directory (run `ralon init`)",
                start.display()
            )
        })?;
        let file = root.join(POLICY_FILE);
        let text = fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        Policy::parse(root, file, &text)
    }

    pub fn parse(root: PathBuf, file: PathBuf, text: &str) -> Result<Policy> {
        // An empty document deserializes into every-field-default, which since
        // `version` stopped being required means an empty `agent.lock` parses
        // cleanly as a policy that protects nothing. The supervisor would then
        // report the project `enforced`, and a developer who ran `touch
        // agent.lock` — or whose file was truncated by a crash or a bad merge —
        // would be told they are covered while every path is writable.
        //
        // Refused here rather than allowed, because "protect nothing" is never
        // worth expressing and "I meant to write a policy" always is. Caught by
        // a test rather than by review: this was the one regression that came
        // with making the version optional.
        if text.lines().all(|line| {
            let line = line.trim();
            line.is_empty() || line == "---" || line.starts_with('#')
        }) {
            bail!(
                "{} is empty, so it protects nothing. Add the paths to protect:\n\
                 \n    protect:\n      - src/auth.ts\n",
                file.display()
            );
        }

        let raw: Raw = serde_yaml_ng::from_str(text)
            .with_context(|| format!("failed to parse {}", file.display()))?;

        if raw.version != CURRENT_VERSION {
            bail!(
                "{}: unsupported version {} (this build understands version {})",
                file.display(),
                raw.version,
                CURRENT_VERSION
            );
        }

        // The policy file protects itself: an agent that can rewrite agent.lock
        // has no policy at all.
        let mut patterns = vec![POLICY_FILE.to_string()];
        for raw_pattern in &raw.protect {
            let pattern = normalize_pattern(raw_pattern)
                .with_context(|| format!("{}: invalid pattern", file.display()))?;
            if !patterns.contains(&pattern) {
                patterns.push(pattern);
            }
        }

        Ok(Policy {
            root,
            file,
            version: raw.version,
            patterns,
        })
    }

    /// Patterns the user wrote, i.e. excluding the implicit `agent.lock` entry.
    pub fn declared_patterns(&self) -> &[String] {
        &self.patterns[1..]
    }
}

/// Rejects anything that could reach outside the project root, and normalizes
/// separators so the same policy behaves identically on every platform.
fn normalize_pattern(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("empty pattern");
    }
    if let Some(rest) = trimmed.strip_prefix('!') {
        bail!("negation is not supported in version 1: `!{rest}`");
    }
    if trimmed.starts_with('~') {
        bail!("`~` is not expanded: `{trimmed}`");
    }

    let unified = trimmed.replace('\\', "/");
    let relative = unified
        .strip_prefix("./")
        .unwrap_or(&unified)
        .trim_start_matches('/')
        .trim_end_matches('/');

    if relative.is_empty() {
        bail!("`{trimmed}` does not name anything inside the project");
    }
    if relative.split('/').any(|part| part == "..") {
        bail!("`..` may not be used to escape the project root: `{trimmed}`");
    }
    // `C:/x` on Windows, `//server/share` anywhere.
    if relative.contains(':') {
        bail!("absolute paths are not allowed, patterns are relative to agent.lock: `{trimmed}`");
    }

    Ok(relative.to_string())
}

/// Makes `path` absolute and resolves `.` and `..` textually.
///
/// Symlinks are deliberately left alone: `check` must answer questions about
/// paths that do not exist yet, and a policy is easier to reason about when it
/// is decided by the path the user wrote.
pub fn absolute(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("failed to resolve {}", path.display()))?;

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            // At the root this is a no-op, so `..` cannot climb out.
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Policy> {
        Policy::parse(PathBuf::from("/p"), PathBuf::from("/p/agent.lock"), text)
    }

    #[test]
    fn parses_minimal_policy() {
        let policy = parse("version: 1\nprotect:\n  - src/index.tsx\n  - config/**\n").unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(
            policy.patterns,
            ["agent.lock", "src/index.tsx", "config/**"]
        );
        assert_eq!(policy.declared_patterns(), ["src/index.tsx", "config/**"]);
    }

    #[test]
    fn protect_defaults_to_empty_but_policy_file_is_always_protected() {
        let policy = parse("version: 1\n").unwrap();
        assert_eq!(policy.patterns, ["agent.lock"]);
    }

    #[test]
    fn duplicate_of_the_implicit_pattern_is_not_repeated() {
        let policy = parse("version: 1\nprotect:\n  - ./agent.lock\n").unwrap();
        assert_eq!(policy.patterns, ["agent.lock"]);
    }

    #[test]
    fn normalizes_separators_and_affixes() {
        let policy = parse("version: 1\nprotect:\n  - /src\\auth.ts\n  - config/\n").unwrap();
        assert_eq!(policy.patterns, ["agent.lock", "src/auth.ts", "config"]);
    }

    #[test]
    fn rejects_unknown_versions() {
        let err = parse("version: 2\nprotect: []\n").unwrap_err().to_string();
        assert!(err.contains("unsupported version 2"), "{err}");
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(parse("version: 1\nallow:\n  - src\n").is_err());
    }

    #[test]
    fn a_policy_needs_no_version() {
        let policy = parse("protect:\n  - src/auth.ts\n").unwrap();
        assert_eq!(policy.version, CURRENT_VERSION);
        assert_eq!(policy.patterns, ["agent.lock", "src/auth.ts"]);
    }

    #[test]
    fn a_policy_that_states_its_version_still_works() {
        // Every `agent.lock` written before this change says `version: 1`, and
        // all of them keep working. Dropping the requirement widens what parses;
        // it must not narrow it.
        let stated = parse("version: 1\nprotect:\n  - src/auth.ts\n").unwrap();
        let unstated = parse("protect:\n  - src/auth.ts\n").unwrap();
        assert_eq!(stated.patterns, unstated.patterns);
        assert_eq!(stated.version, unstated.version);
    }

    #[test]
    fn something_that_is_not_a_policy_is_still_rejected() {
        // The risk in making `version` optional: a file that means nothing must
        // not now parse as a policy protecting nothing, because that is the
        // failure this whole program exists to prevent — a developer believing
        // they are covered while every path is writable.
        //
        // `deny_unknown_fields` is what actually catches these, which is why the
        // version field was not doing the work its presence implied.
        for text in [
            "",                            // empty
            "\n\n   \n",                   // blank
            "# just a comment\n",          // nothing but a comment
            "---\n",                       // an empty document
            "name: my-app\nversion: 1\n",  // some other project's YAML
            "protects:\n  - src\n",        // a typo in the only key that matters
            "- src/auth.ts\n",             // a bare list
            "protect: src/auth.ts\n",      // a string where a list belongs
        ] {
            assert!(
                parse(text).is_err(),
                "parsed as a valid policy, protecting nothing: {text:?}"
            );
        }
    }

    #[test]
    fn the_template_needs_no_version_either() {
        // `init` writes TEMPLATE, so if it still said `version: 1` the field
        // would go on being copied into every new project by the tool itself.
        assert!(!TEMPLATE.contains("version"), "{TEMPLATE}");
        assert!(parse(TEMPLATE).is_ok());
    }

    #[test]
    fn rejects_escaping_patterns() {
        for pattern in [
            "../outside",
            "src/../../etc",
            "~/.ssh",
            "!src/a.ts",
            "C:/win",
        ] {
            let text = format!("version: 1\nprotect:\n  - \"{pattern}\"\n");
            assert!(parse(&text).is_err(), "accepted {pattern}");
        }
    }
}
