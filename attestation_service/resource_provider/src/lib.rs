#[cfg(feature = "co-deployment")]
mod local;

#[cfg(feature = "independent-deployment")]
mod restful;

pub mod factory;
pub mod error;

pub mod resource_facade;
pub mod routes;

// Ensure feature mutual exclusivity at compile time
#[cfg(all(
    feature = "co-deployment",
    feature = "independent-deployment"
))]
compile_error!(
    "`co-deployment` and `independent-deployment` cannot be enabled together. \
    Hint: When using `independent-deployment`, add `default-features = false`"
);