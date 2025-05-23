use std::future::Future;
use std::pin::Pin;
use common_log::info;
use crate::init_chain::traits::{InitContext, InitHandler};

#[derive(Debug)]
pub struct LoggerInitHandler {
    next: Option<Box<dyn InitHandler>>,
}

impl LoggerInitHandler {
    pub fn new() -> LoggerInitHandler {
        LoggerInitHandler { next: None }
    }

    pub fn init_logger(&self) {
        common_log::init().expect("Failed to initialize logger");
        info!("Logger initialized");
    }
}

impl InitHandler for LoggerInitHandler {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output=Result<(), String>> + 'a>> {
        Box::pin(async move {
            self.init_logger();
            if let Some(next) = &self.next {
                next.handle(context).await
            } else {
                Ok(())
            }
        })
    }

    fn set_next(&mut self, next: Box<dyn InitHandler>) {
        self.next = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use super::*;

    fn write_yaml_config() {
        let yaml_content: String = format!(
            r#"loggers:
  - path_prefix: root
    log_directory: logs
    log_file_name: root.log
    max_file_size: 10485760  # 10MB
    max_zip_count: 5
    level: info
"#
        );
        let mut file = File::create("logging.yaml").unwrap();
        let _ = file.write_all(yaml_content.as_bytes());
        println!("YAML file created.");
    }

    fn delete_test_file() {
        let current_dir = std::env::current_dir().unwrap();
        let yml = current_dir.join("logging.yaml");
        if yml.exists() {
            let _ = fs::remove_file(yml);
            println!("YAML file deleted");
        }
        let yml = current_dir.join("ra-log");
        if yml.exists() {
            let _ = fs::remove_dir_all(yml);
            println!("YAML file deleted");
        }
    }

    #[tokio::test]
    async fn test() {
        write_yaml_config();
        let handler = LoggerInitHandler::new();
        let mut context = InitContext::new();
        let result = handler.handle(&mut context).await;
        info!("init successful");
        assert!(result.is_ok());
        delete_test_file();
    }
}