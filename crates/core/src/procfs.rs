use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxProcStat {
    pub comm: String,
    pub start_time_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LinuxProcStatParseError {
    #[error("missing opening comm delimiter")]
    MissingOpeningCommDelimiter,
    #[error("missing closing comm delimiter")]
    MissingClosingCommDelimiter,
    #[error("invalid comm delimiters")]
    InvalidCommDelimiters,
    #[error("missing starttime field")]
    MissingStartTime,
    #[error("invalid starttime field: {reason}")]
    InvalidStartTime { reason: String },
}

pub fn parse_linux_proc_stat(content: &str) -> Result<LinuxProcStat, LinuxProcStatParseError> {
    let open = content
        .find('(')
        .ok_or(LinuxProcStatParseError::MissingOpeningCommDelimiter)?;
    let close = content
        .rfind(')')
        .ok_or(LinuxProcStatParseError::MissingClosingCommDelimiter)?;
    if close <= open {
        return Err(LinuxProcStatParseError::InvalidCommDelimiters);
    }
    let comm = content[open + 1..close].to_string();
    let start_time_ticks = content[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(LinuxProcStatParseError::MissingStartTime)?
        .parse::<u64>()
        .map_err(|source| LinuxProcStatParseError::InvalidStartTime {
            reason: source.to_string(),
        })?;
    Ok(LinuxProcStat {
        comm,
        start_time_ticks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_proc_stat_parser_handles_comm_with_parenthesis() {
        let stat = parse_linux_proc_stat(
            "123 (name ) with paren) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20",
        )
        .expect("valid stat should parse");

        assert_eq!(stat.comm, "name ) with paren");
        assert_eq!(stat.start_time_ticks, 99);
    }
}
