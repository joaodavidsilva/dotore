//! Thin CLI adapter for `dotore` (argument parsing and exit code only).

use std::process::ExitCode;

use clap::Parser;
use dotore::{Cli, run_cli};

fn main() -> ExitCode {
    run_cli(Cli::parse())
}
