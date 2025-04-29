//! Define Lua scripts for distributed lock operations

/// Lua script for releasing lock
/// Can only release the lock when it exists and the value matches
pub const RELEASE_LOCK: &str = r#"
    if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('del', KEYS[1])
    end
    return 0
"#;

/// Lua script for extending lock expiration time
/// Can only extend expiration time when the lock exists and the value matches
pub const EXTEND_LOCK: &str = r#"
    if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('expire', KEYS[1], ARGV[2])
    end
    return 0
"#;