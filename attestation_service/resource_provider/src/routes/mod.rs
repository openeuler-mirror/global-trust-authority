/// Registering routes

pub mod register;
#[cfg(feature = "co-deployment")]
pub mod local;

#[cfg(feature = "independent-deployment")]
pub mod remote;