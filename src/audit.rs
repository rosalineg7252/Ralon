//! Conditions that quietly weaken a policy.
//!
//! Both backends protect *paths*. Anything that gives a protected file a second
//! name, or the project a second mount point, is a way to reach the same bytes
//! without going through a path Ralon restricted. None of it can be fixed by
//! enforcing harder — the kernel is already doing what it was asked — so the
//! only honest response is to say so before the agent starts.

use std::path::Path;

use crate::scan::ProtectedPath;

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub subject: String,
    pub detail: String,
}

/// Everything worth telling the user before `run` hands over.
pub fn audit(root: &Path, protected: &[ProtectedPath]) -> Vec<Finding> {
    let mut findings = hard_links(protected);
    findings.extend(second_mounts(root));
    findings.extend(already_open_for_writing(protected));
    findings
}

/// A protected file that something else already has open for writing.
///
/// Not a weakness in the policy — the opposite. It is a file that is *in use*:
/// a live SQLite database, a log a dev server appends to, a state file some
/// daemon rewrites. Protecting it either fails to take the lock, or takes it
/// and breaks the program that was using it, and both look like Ralon
/// misbehaving rather than like a policy naming the wrong thing.
///
/// Windows only, because it is the only platform here that can answer the
/// question. Unix has no mandatory locking, so an open file for writing is
/// indistinguishable from a closed one without walking every process.
#[cfg(windows)]
fn already_open_for_writing(protected: &[ProtectedPath]) -> Vec<Finding> {
    use std::os::windows::fs::OpenOptionsExt;

    /// The share mode enforcement itself will ask for. If this open is refused,
    /// so is that one, and for the same reason.
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    /// `ERROR_SHARING_VIOLATION` and `ERROR_LOCK_VIOLATION`. Only these two
    /// mean "somebody else has it"; a missing file or a permissions problem is
    /// a different complaint with a different answer.
    const IN_USE: [i32; 2] = [32, 33];

    protected
        .iter()
        .filter(|path| !path.is_dir)
        .filter(|path| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&path.absolute)
                .err()
                .and_then(|error| error.raw_os_error())
                .is_some_and(|code| IN_USE.contains(&code))
        })
        .map(|path| Finding {
            subject: path.relative.clone(),
            detail: "is held open by another process, so it cannot be locked — protect \
                     the files a program owns, not the ones it is using"
                .to_string(),
        })
        .collect()
}

#[cfg(not(windows))]
fn already_open_for_writing(_protected: &[ProtectedPath]) -> Vec<Finding> {
    Vec::new()
}

/// A protected file with more than one name.
///
/// The other names are ordinary files: not bind-mounted, not carved out of the
/// Landlock grant, and writing one changes the protected file's contents. This
/// is invisible unless you go looking, which is why it is checked every run.
#[cfg(unix)]
fn hard_links(protected: &[ProtectedPath]) -> Vec<Finding> {
    use std::os::unix::fs::MetadataExt;

    protected
        .iter()
        .filter(|path| !path.is_dir)
        .filter_map(|path| {
            let links = std::fs::metadata(&path.absolute).ok()?.nlink();
            (links > 1).then(|| Finding {
                subject: path.relative.clone(),
                detail: format!(
                    "has {links} hard links; the other names are not protected and \
                     writing one changes this file"
                ),
            })
        })
        .collect()
}

#[cfg(not(unix))]
fn hard_links(_protected: &[ProtectedPath]) -> Vec<Finding> {
    Vec::new()
}

/// The project reachable at a second mount point.
///
/// A bind mount made before the sandbox starts is a complete bypass of both
/// backends: the protected paths were restricted, that path was not. The
/// sandboxed process cannot create one, so finding it here is the only warning
/// anyone gets.
#[cfg(target_os = "linux")]
fn second_mounts(root: &Path) -> Vec<Finding> {
    let Ok(table) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    second_mounts_from(root, &table)
}

#[cfg(not(target_os = "linux"))]
fn second_mounts(_root: &Path) -> Vec<Finding> {
    Vec::new()
}

/// One line of `/proc/self/mountinfo`, reduced to what matters here.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Mount<'a> {
    device: &'a str,
    /// The subtree of the filesystem this mount exposes.
    root: &'a str,
    point: &'a str,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse(table: &str) -> Vec<Mount<'_>> {
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let root = fields.nth(3)?;
            let point = fields.next()?;
            // Optional fields run until a lone "-", then: fstype, source, opts.
            let device = fields.skip_while(|field| *field != "-").nth(2)?;
            Some(Mount {
                device,
                root,
                point,
            })
        })
        .collect()
}

/// Split so the parsing can be tested without a filesystem to mount things on.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn second_mounts_from(root: &Path, table: &str) -> Vec<Finding> {
    let mounts = parse(table);
    let Some(root) = root.to_str() else {
        return Vec::new();
    };

    // The mount the project actually lives on is the longest mount point that
    // is a prefix of it.
    let Some(home) = mounts
        .iter()
        .filter(|mount| under(root, mount.point))
        .max_by_key(|mount| mount.point.len())
    else {
        return Vec::new();
    };

    // Where the project sits inside its filesystem, which is what another mount
    // of the same filesystem would have to expose to reach it.
    let inside = join(home.root, strip(root, home.point));

    mounts
        .iter()
        .filter(|mount| mount.point != home.point)
        .filter(|mount| mount.device == home.device)
        .filter(|mount| under(&inside, mount.root))
        .map(|mount| Finding {
            subject: join(mount.point, strip(&inside, mount.root)),
            detail: "is a second path to this project; writes through it are not \
                     restricted by either backend"
                .to_string(),
        })
        .collect()
}

/// Whether `path` is at or below `prefix`, comparing whole components.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn under(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// The part of `path` below `prefix`, without a leading separator.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn strip<'a>(path: &'a str, prefix: &str) -> &'a str {
    if prefix == "/" {
        return path.trim_start_matches('/');
    }
    path.strip_prefix(prefix.trim_end_matches('/'))
        .unwrap_or("")
        .trim_start_matches('/')
}

/// Joins a mount point to a remainder with exactly one separator. Both sides
/// can be "/", which is what made the naive version silently produce paths
/// with no leading slash — and match nothing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn join(base: &str, remainder: &str) -> String {
    let base = base.trim_end_matches('/');
    if remainder.is_empty() {
        return if base.is_empty() {
            "/".into()
        } else {
            base.into()
        };
    }
    format!("{base}/{remainder}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries: the root filesystem, and a bind mount of /home/dev/proj
    /// exposed a second time at /mnt/copy.
    const TABLE: &str = "\
25 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
26 25 8:1 /home/dev/proj /mnt/copy rw,relatime shared:1 - ext4 /dev/sda1 rw
27 25 0:22 / /proc rw,relatime shared:2 - proc proc rw";

    #[test]
    fn finds_a_bind_mount_of_the_project() {
        let findings = second_mounts_from(Path::new("/home/dev/proj"), TABLE);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].subject, "/mnt/copy");
    }

    #[test]
    fn finds_the_project_inside_a_bind_mounted_parent() {
        let findings = second_mounts_from(Path::new("/home/dev/proj/src"), TABLE);
        assert_eq!(findings[0].subject, "/mnt/copy/src");
    }

    #[test]
    fn a_project_that_is_mounted_once_reports_nothing() {
        let findings = second_mounts_from(Path::new("/home/dev/other"), TABLE);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_different_filesystem_at_another_point_is_not_a_second_path() {
        let table = "\
25 0 8:1 / / rw - ext4 /dev/sda1 rw
26 25 8:2 / /mnt/other rw - ext4 /dev/sdb1 rw";
        assert!(second_mounts_from(Path::new("/home/dev/proj"), table).is_empty());
    }

    #[test]
    fn prefix_matching_respects_component_boundaries() {
        assert!(under("/a/b", "/a"));
        assert!(under("/a", "/a"));
        assert!(under("/anything", "/"));
        assert!(!under("/ab", "/a"), "/ab is not inside /a");
    }
}
