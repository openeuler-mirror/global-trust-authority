#[cfg(test)]
mod tests {
    use key_managerd::key_manager::base_key_manager::{PrivateKey};

    #[test]
    fn test_private_key_default() {
        let key = PrivateKey::default();
        assert!(key.version.is_empty());
        assert!(key.private_key.is_empty());
        assert!(key.algorithm.is_empty());
        assert!(key.encoding.is_empty());
    }

    #[test]
    fn test_private_key_new() {
        let key = PrivateKey::new("v1".to_string(), "test_key".to_string(), "RSA".to_string(), "PEM".to_string());
        assert_eq!(key.version, "v1");
        assert_eq!(key.private_key, "test_key");
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.encoding, "PEM");
    }
}