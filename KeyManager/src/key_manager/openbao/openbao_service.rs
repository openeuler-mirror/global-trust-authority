use serde::{Deserialize, Serialize};



#[derive(Serialize, Deserialize)]
pub struct Version {
    pub created_time : String,
    pub deletion_time : String,
    pub destroyed : bool
}