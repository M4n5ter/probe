use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub(crate) const DEFAULT_TAIL_BYTES: u64 = 8 * 1024;

pub(crate) fn read_text_tail(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    let read_start = start.saturating_sub(1);
    file.seek(SeekFrom::Start(read_start))?;

    let mut bytes = Vec::new();
    let max_read = max_bytes.saturating_add(u64::from(start > 0));
    file.take(max_read).read_to_end(&mut bytes)?;
    if start > 0 {
        match bytes.first() {
            Some(b'\n') => {
                bytes.remove(0);
            }
            Some(_) => match bytes.iter().position(|byte| *byte == b'\n') {
                Some(index) => {
                    bytes.drain(..=index);
                }
                None => {
                    bytes.remove(0);
                }
            },
            None => {}
        }
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

pub(crate) fn last_non_empty_lines(text: &str, max_lines: usize) -> Vec<&str> {
    text.lines()
        .rev()
        .filter(|line| !line.trim().is_empty())
        .take(max_lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

pub(crate) fn one_line_tail(text: &str, max_lines: usize) -> String {
    last_non_empty_lines(text, max_lines).join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_text_tail_bounds_large_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("agent.log");
        std::fs::write(&path, "first\nsecond\nthird\n")?;

        assert_eq!(read_text_tail(&path, 12)?, "third\n");
        Ok(())
    }

    #[test]
    fn read_text_tail_keeps_first_line_when_starting_on_line_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("agent.log");
        std::fs::write(&path, "first\nsecond\nthird\n")?;

        assert_eq!(read_text_tail(&path, 13)?, "second\nthird\n");
        Ok(())
    }

    #[test]
    fn read_text_tail_preserves_long_partial_line_suffix() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("agent.log");
        std::fs::write(&path, "abcdefg")?;

        assert_eq!(read_text_tail(&path, 4)?, "defg");
        Ok(())
    }

    #[test]
    fn read_text_tail_preserves_leading_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("agent.log");
        std::fs::write(&path, "  indented\n")?;

        assert_eq!(read_text_tail(&path, 128)?, "  indented\n");
        Ok(())
    }

    #[test]
    fn one_line_tail_uses_last_non_empty_lines() {
        assert_eq!(
            one_line_tail("one\n\ntwo\nthree\nfour\n", 2),
            "three | four"
        );
    }
}
