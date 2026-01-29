use crate::validation::comprehensive::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_key_detection() {
        assert!(is_all_zeros(&[0; 32]));
        assert!(!is_all_zeros(&[0; 31]));
        assert!(!is_all_zeros(&[1; 32]));
    }
}