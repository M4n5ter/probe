pub(crate) const INLINE_TEXT_MAX_CHARS: usize = 512;

pub(crate) fn terminal_safe_inline_text(text: impl Into<String>) -> String {
    let mut normalized = String::new();
    let mut last_was_space = false;
    for character in text.into().chars() {
        let next = if character.is_control() {
            ' '
        } else {
            character
        };
        if next.is_whitespace() {
            if !last_was_space {
                normalized.push(' ');
            }
            last_was_space = true;
        } else {
            normalized.push(next);
            last_was_space = false;
        }
    }
    truncate_inline_text(normalized.trim())
}

fn truncate_inline_text(text: &str) -> String {
    if text.chars().count() <= INLINE_TEXT_MAX_CHARS {
        return text.to_string();
    }
    let keep = INLINE_TEXT_MAX_CHARS.saturating_sub(3);
    let mut truncated = text.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_safe_inline_text_removes_controls_and_bounds_length() {
        let raw = format!(
            "startup failed\nstderr: \x1b[31m{}\tmore",
            "x".repeat(INLINE_TEXT_MAX_CHARS * 2)
        );

        let text = terminal_safe_inline_text(raw);

        assert!(!text.chars().any(char::is_control));
        assert!(text.chars().count() <= INLINE_TEXT_MAX_CHARS);
        assert!(text.contains("startup failed stderr:"));
        assert!(text.ends_with("..."));
    }

    #[test]
    fn terminal_safe_inline_text_preserves_short_text() {
        assert_eq!(terminal_safe_inline_text("ready"), "ready");
    }
}
