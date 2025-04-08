use std::io;
use std::process::{Command, Output};

pub trait CommandExecutor {
    
    fn execute(&self, command: &str, args: &Vec<String>) -> io::Result<Output> {
        log::info!("Executing {:?}", command);
        let output = Command::new(command).args(args).output();
        match output {
            Ok(output) => {
                log::info!("Output {:?}", String::from_utf8_lossy(&output.stdout));
                Ok(output)
            },
            Err(error) => {Err(error)}
        }
    }
    
    fn run(&self) -> io::Result<Output>;

}
