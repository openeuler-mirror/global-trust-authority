/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

pub mod commands;

use crate::commands::put::{PutArgs, handle_put};
use clap::Parser;
use std::process::exit;
use key_managerd::utils::env_setting_center::load_env;
use key_managerd::utils::logger::init_logger;

#[derive(Parser)]
#[command(name = "key_manager")]
#[command(about = "Key Manager CLI Tool", version = "0.1.0")]
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
    match load_env() {
        Ok(_) => {}
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    };
    init_logger(false).expect("failed to init logger");
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Put(args) => handle_put(args),
    };
    match result {
        Ok(_) => {
            log::info!("success to handle command");
            println!("success to handle command");
        }
        Err(e) => {
            log::error!("failed to handle command,error: {}", e);
            eprintln!("{}", e);
            exit(1);
        }
    }
}
