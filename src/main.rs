//! Ralon — `agent.lock` declares what AI agents may not modify, and this
//! binary makes the kernel agree.

mod cli;
mod commands;
mod enforce;
mod matcher;
mod policy;
mod scan;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};

/// Something went wrong; nothing was enforced.
const ERROR: u8 = 2;

/// Rust ignores `SIGPIPE`, which turns `ralon check | head` into a panic
/// about a broken pipe instead of a quiet exit. Put the default back.
#[cfg(target_os = "linux")]
fn restore_sigpipe() {
    // Safety: called once, at startup, before any thread exists.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

#[cfg(not(target_os = "linux"))]
fn restore_sigpipe() {}

fn main() -> ExitCode {
    restore_sigpipe();
    match dispatch() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("ralon: {error:#}");
            ExitCode::from(ERROR)
        }
    }
}

fn dispatch() -> Result<ExitCode> {
    let cli = Cli::parse();
    let directory = match cli.directory {
        Some(directory) => directory,
        None => std::env::current_dir()?,
    };

    match cli.command {
        Command::Init { force } => commands::init(&directory, force),
        Command::Check { paths } => commands::check(&directory, &paths),
        Command::Status => commands::status(&directory),
        Command::Run {
            backend,
            dry_run,
            quiet,
            command,
        } => commands::run(&directory, backend, dry_run, quiet, &command),
    }
}
