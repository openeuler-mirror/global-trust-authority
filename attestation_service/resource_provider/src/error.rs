#[derive(Debug)]
#[allow(warnings)]
pub struct ConfigManagerError {
    message: String,
}

#[allow(warnings)]
impl ConfigManagerError {
    pub fn new<T: Into<String>>(message: T) -> Self {
        ConfigManagerError {
            message: message.into(),
        }
    }
}

