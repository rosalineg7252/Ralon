//! The Landlock LSM: an additive carve-out, applied to this process.
//!
//! Landlock rules only ever grant, so "everything except this file" has to be
//! expressed by granting every sibling on the way down. `enforce::carve` works
//! that out — on any platform, so `--dry-run` can show it — and this file only
//! hands the result to the kernel.

use std::ptr;

use anyhow::{bail, Result};
use landlock::{
    path_beneath_rules, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use crate::enforce::carve::Carve;
use crate::enforce::Availability;

/// The last Landlock ABI whose write set means exactly "modify a file". Later
/// ABIs add device ioctls (v5) and unix socket connects (v9), which a policy
/// about file contents has no business denying. Older kernels are handled by
/// `CompatLevel::BestEffort`.
const LANDLOCK_ABI: ABI = ABI::V3;

pub fn availability() -> Availability {
    match abi() {
        Some(version) if version >= 2 => Availability::Available {
            detail: format!("kernel ABI v{version}"),
        },
        Some(version) => Availability::Available {
            detail: format!("kernel ABI v{version}, no cross-directory renames"),
        },
        None => Availability::Unavailable {
            reason: "the kernel reports no Landlock support (needs Linux 5.13+ with landlock \
                     enabled, e.g. lsm=landlock,... on the kernel command line)"
                .to_string(),
        },
    }
}

fn abi() -> Option<i64> {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    (version > 0).then_some(version)
}

pub fn apply(carve: &Carve) -> Result<()> {
    if carve.restricted.is_empty() {
        return Ok(());
    }

    let access = AccessFs::from_write(LANDLOCK_ABI);
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access)?
        .create()?
        .no_new_privs(true)
        .add_rules(path_beneath_rules(&carve.granted, access))?
        .restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            eprintln!(
                "ralon: warning: this kernel supports only part of the policy; \
                 run `ralon status` for details"
            );
            Ok(())
        }
        RulesetStatus::NotEnforced => {
            bail!("the kernel accepted no part of the policy — nothing is protected")
        }
    }
}
