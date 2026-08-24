use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::enforce::Backend;

/// Filesystem policy for AI coding agents.
///
/// `agent.lock` declares what AI-controlled processes may not modify, the same
/// way `.gitignore` declares what Git may not track.
#[derive(Debug, Parser)]
#[command(name = "ralon", version, about, long_about = None)]
pub struct Cli {
    /// Directory to look for agent.lock in (default: the current directory)
    #[arg(short = 'C', long = "dir", global = true, value_name = "DIR")]
    pub directory: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a starter agent.lock
    Init {
        /// Overwrite an existing agent.lock
        #[arg(long)]
        force: bool,
    },

    /// Report what the policy protects, or whether given paths are protected
    ///
    /// Exits 1 if any given path is protected, which makes it usable as an
    /// agent pre-write hook.
    Check {
        /// Paths to test. With none, lists everything the policy protects.
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,
    },

    /// Show the policy and which enforcement backends this kernel offers
    Status,

    /// Install or run the agent hook
    ///
    /// The hook refuses an agent's own edit tools before they touch a protected
    /// path. It is a courtesy layer, not enforcement — an agent that shells out
    /// bypasses it — but on platforms `run` cannot restrict, it is the only
    /// thing standing between an agent and your policy.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Run a command that cannot modify the protected paths
    Run {
        /// Enforcement backend
        #[arg(long, value_enum, default_value_t = Backend::Auto)]
        backend: Backend,

        /// Print what would be enforced and exit
        #[arg(long)]
        dry_run: bool,

        /// Do not print the lock summary before running
        #[arg(short, long)]
        quiet: bool,

        /// Command to run, e.g. `ralon run -- claude`
        #[arg(
            value_name = "COMMAND",
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<OsString>,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Wire the hook into an agent's configuration
    Install {
        /// Which agent to configure
        #[arg(long, value_enum, default_value_t = Agent::All)]
        agent: Agent,

        /// Print the configuration instead of writing it
        #[arg(long)]
        dry_run: bool,
    },

    /// Decide one edit, reading the agent's request on stdin
    ///
    /// This is what the installed hook calls. Parsing the request here rather
    /// than in a shell snippet keeps the configuration free of quoting, and
    /// means the hook behaves identically on every platform.
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    /// Every agent below. A policy should hold whichever tool the project is
    /// opened with, and you cannot know that in advance.
    All,
    /// Claude Code — .claude/settings.json
    Claude,
    /// Cursor — .cursor/hooks.json
    Cursor,
    /// OpenCode — .opencode/plugins/ralon.js
    Opencode,
}
