use std::{error::Error, fmt, path::PathBuf};

#[derive(Debug)]
pub(crate) enum DynSslError {
    LoadLibrary {
        path: PathBuf,
        reason: String,
    },
    ResolveSymbol {
        path: PathBuf,
        symbol: &'static str,
        reason: String,
    },
    NullPointer {
        action: &'static str,
    },
    OpenSsl {
        action: &'static str,
    },
    Io {
        action: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for DynSslError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadLibrary { path, reason } => {
                write!(
                    formatter,
                    "failed to load dynamic libssl {}: {reason}",
                    path.display()
                )
            }
            Self::ResolveSymbol {
                path,
                symbol,
                reason,
            } => write!(
                formatter,
                "failed to resolve {symbol} from dynamic libssl {}: {reason}",
                path.display()
            ),
            Self::NullPointer { action } => write!(
                formatter,
                "dynamic libssl returned null while trying to {action}"
            ),
            Self::OpenSsl { action } => write!(formatter, "dynamic libssl failed to {action}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
        }
    }
}

impl Error for DynSslError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::LoadLibrary { .. }
            | Self::ResolveSymbol { .. }
            | Self::NullPointer { .. }
            | Self::OpenSsl { .. } => None,
        }
    }
}

pub(crate) fn io_error(action: &'static str, source: std::io::Error) -> DynSslError {
    DynSslError::Io { action, source }
}
