use crate::common::validation::{validate_message_length, validate_non_empty_message};

pub fn validate_message(message: &[u8]) -> Result<(), String> {
    validate_non_empty_message(message)?;
    validate_message_length(message, 1000)?;
    Ok(())
}
