#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Weak key detected")]
    WeakKey,

    #[error("Invalid parameter set")]
    InvalidParameterSet,

    #[error("Invalid encoding")]
    InvalidEncoding,

    #[error("Key validation failed")]
    ValidationFailed,
}

pub type ValidationResult<T> = Result<T, ValidationError>;

pub fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

pub fn validate_ml_kem_public_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_ml_kem_secret_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_ml_dsa_public_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_ml_dsa_secret_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_slh_dsa_public_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_slh_dsa_secret_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_fn_dsa_public_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_fn_dsa_secret_key(key: &[u8], expected_size: usize) -> ValidationResult<()> {
    if key.len() != expected_size {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_aes_gcm_key(key: &[u8]) -> ValidationResult<()> {
    const VALID_SIZES: [usize; 2] = [16, 32];
    if !VALID_SIZES.contains(&key.len()) {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_ecdh_public_key(key: &[u8]) -> ValidationResult<()> {
    if key.len() != 32 {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

pub fn validate_ecdh_secret_key(key: &[u8]) -> ValidationResult<()> {
    if key.len() != 32 {
        return Err(ValidationError::InvalidKeyFormat);
    }
    if is_all_zeros(key) {
        return Err(ValidationError::WeakKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_key_detection() {
        assert!(is_all_zeros(&[0; 32]));
        assert!(!is_all_zeros(&[0; 31]));
        assert!(!is_all_zeros(&[1; 32]));
    }

    #[test]
    fn test_ml_kem_validation() {
        let valid_key = vec![1u8; 1184];
        assert!(validate_ml_kem_public_key(&valid_key, 1184).is_ok());
        assert!(validate_ml_kem_secret_key(&valid_key, 2400).is_ok());

        let wrong_size = vec![1u8; 1000];
        assert!(validate_ml_kem_public_key(&wrong_size, 1184).is_err());

        let weak_key = vec![0u8; 1184];
        assert!(validate_ml_kem_public_key(&weak_key, 1184).is_err());
    }

    #[test]
    fn test_aes_gcm_validation() {
        let valid_128 = vec![1u8; 16];
        let valid_256 = vec![1u8; 32];
        assert!(validate_aes_gcm_key(&valid_128).is_ok());
        assert!(validate_aes_gcm_key(&valid_256).is_ok());

        let invalid_size = vec![1u8; 24];
        assert!(validate_aes_gcm_key(&invalid_size).is_err());

        let weak_key = vec![0u8; 16];
        assert!(validate_aes_gcm_key(&weak_key).is_err());
    }

    #[test]
    fn test_ecdh_validation() {
        let valid_key = vec![1u8; 32];
        assert!(validate_ecdh_public_key(&valid_key).is_ok());
        assert!(validate_ecdh_secret_key(&valid_key).is_ok());

        let wrong_size = vec![1u8; 31];
        assert!(validate_ecdh_public_key(&wrong_size).is_err());

        let weak_key = vec![0u8; 32];
        assert!(validate_ecdh_public_key(&weak_key).is_err());
    }
}