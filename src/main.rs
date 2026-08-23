//! Agent Lock — `agent.lock` declares what AI agents may not modify, and this
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

fn main() -> ExitCode {
    match dispatch() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("agent-lock: {error:#}");
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
