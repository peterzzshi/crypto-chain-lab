use encryption_demo::rsa::text_encoding::{number_to_text, text_to_number};
use num_bigint::BigUint;

#[test]
fn text_to_number_roundtrip() {
    let text = "Hi";
    let n = text_to_number(text).unwrap();
    assert_eq!(text, number_to_text(&n).as_str());
}

#[test]
fn text_to_number_empty_is_none() {
    assert!(text_to_number("").is_none());
}

#[test]
fn text_to_number_is_unique() {
    assert_ne!(text_to_number("Hi").unwrap(), text_to_number("Bye").unwrap());
}

#[test]
fn long_text_is_supported() {
    let text = "Hello World";
    let n = text_to_number(text).unwrap();
    assert_eq!(text, number_to_text(&n).as_str());
}

#[test]
fn number_to_text_zero_is_empty_or_null() {
    let result = number_to_text(&BigUint::from(0u32));
    assert!(result.is_empty() || result.as_bytes().iter().all(|&b| b == 0));
}
