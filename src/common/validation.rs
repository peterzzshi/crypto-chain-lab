pub fn validate_non_empty_message(message: &[u8]) -> Result<(), String> {
    if message.is_empty() {
        return Err("Message cannot be empty".to_string());
    }
    Ok(())
}

pub fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (32..=126).contains(&b))
}

pub fn validate_message_length(message: &[u8], max_length: usize) -> Result<(), String> {
    if message.len() > max_length {
        return Err(format!("Message too long (max {} bytes)", max_length));
    }
    Ok(())
}
