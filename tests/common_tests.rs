mod common;
use encryption_demo::common::validation::{is_printable_ascii, validate_message_length, validate_non_empty_message};

#[test]
fn test_validate_non_empty_message() {
    assert!(validate_non_empty_message(b"test").is_ok());
    assert!(validate_non_empty_message(b"").is_err());
}

#[test]
fn test_validate_message_length() {
    let short_message = vec![0u8; 100];
    let long_message = vec![0u8; 2000];

    assert!(validate_message_length(&short_message, 1000).is_ok());
    assert!(validate_message_length(&long_message, 1000).is_err());
}

#[test]
fn test_is_printable_ascii() {
    assert!(is_printable_ascii(b"Hello World!"));
    assert!(is_printable_ascii(b"123 ABC xyz"));
    assert!(!is_printable_ascii(&[0, 1, 2, 3]));
    assert!(!is_printable_ascii(&[200, 201, 202]));
}
