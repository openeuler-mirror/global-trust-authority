pub mod commands;

use crate::commands::put::{PutArgs, handle_put};
use KeyManager::utils::env_setting_center::{Environment, load_env};
use KeyManager::utils::logger::init_logger;
use clap::Parser;
use std::process::exit;

#[derive(Parser)]
#[command(name = "key_manager")]
#[command(about = "Key Manager CLI Tool", version = "0.0.1")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Sets or updates private key
    Put(PutArgs),
}

fn main() {
    load_env();
    match Environment::check() {
        Ok(_) => {}
        Err(err) => {
            log::error!("load env config error, message: {}", err);
            exit(1);
        }
    }
    init_logger(false).expect("failed to init logger");

    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Put(args) => handle_put(args),
    };
    match result {
        Ok(_) => {
            println!("success to handle command");
        }
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    }
}
