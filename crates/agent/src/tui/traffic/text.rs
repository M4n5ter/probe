use probe_core::Direction;

pub(super) fn fit_preview_lines(mut lines: Vec<String>, max_lines: usize) -> Vec<String> {
    let max_lines = max_lines.max(1);
    if lines.len() <= max_lines {
        return lines;
    }
    let prompt = lines.pop().unwrap_or_else(|| "Open detail".to_string());
    lines.truncate(max_lines);
    if let Some(last) = lines.last_mut() {
        *last = prompt;
    }
    lines
}

pub(super) fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "in",
        Direction::Outbound => "out",
    }
}

pub(super) fn bytes_detail(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => escape_text(text),
        Err(_) => format!("hex: {}", hex_or_dash(bytes)),
    }
}

pub(super) fn hex_or_dash(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

pub(super) fn escape_text(value: &str) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    let mut output = String::new();
    for character in value.chars() {
        for escaped in character.escape_default() {
            output.push(escaped);
        }
    }
    output
}
