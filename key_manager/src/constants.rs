// 编码类型 pem
pub const ENCODING_PEM: &str = "pem";

// 算法类型
pub const ALGORITHM_RSA_3072: &str = "rsa_3072";
pub const ALGORITHM_RSA_4096: &str = "rsa_4096";
pub const ALGORITHM_EC: &str = "ec";
pub const ALGORITHM_SM2: &str = "sm2";

pub const RSA_3072_KEY_SIZE: u32 = 3072;
pub const RSA_4096_KEY_SIZE: u32 = 4096;

pub const MAX_PRIVATE_KEY_SIZE: u64 = 10 * 1024 * 1024; // 10MB