//! Ralon — `agent.lock` declares what AI agents may not modify, and this
//! binary makes the kernel agree.

mod audit;
mod cli;
mod commands;
mod enforce;
mod hook;
mod matcher;
mod policy;
mod scan;
mod service;
mod supervisor;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command, HookAction, ScopeAction};

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
        Command::Install {
            scope,
            depth,
            no_hooks,
            dry_run,
        } => commands::install(&scope, depth, no_hooks, dry_run),
        Command::Scope { action } => match action {
            ScopeAction::Add { directories } => commands::scope_add(&directories),
            ScopeAction::List => commands::scope_list(),
            ScopeAction::Remove { directories } => commands::scope_remove(&directories),
        },
        Command::Uninstall { keep_enforcement } => commands::uninstall(keep_enforcement),
        Command::Pause {
            minutes,
            indefinitely,
        } => commands::pause(&directory, minutes, indefinitely),
        Command::Resume => commands::resume(&directory),
        Command::Daemon {
            foreground,
            once,
            home,
        } => commands::daemon(foreground, once, home),
        Command::Init { force, no_hooks } => commands::init(&directory, force, no_hooks),
        Command::Check { paths } => commands::check(&directory, &paths),
        Command::Status => commands::status(&directory),
        Command::Guard {
            detach,
            stop,
            detached,
        } => commands::guard(&directory, detach, stop, detached),
        Command::Hook { action } => match action {
            HookAction::Install { agent, dry_run } => {
                commands::hook_install(&directory, agent, dry_run)
            }
            HookAction::Check => commands::hook_check(&directory),
        },
        Command::Run {
            backend,
            dry_run,
            quiet,
            command,
        } => commands::run(&directory, backend, dry_run, quiet, &command),
    }
}
