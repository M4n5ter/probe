use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use probe_config::{AgentConfig, TlsMaterialConfig, TlsMaterialKind};

use super::fixture::SyntheticTls13AutoBindingFixture;

const SESSION_SECRET_ID: &str = "tls-session-secrets";
const KEY_LOG_ID: &str = "tls-key-log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AutoBindingScenario {
    source: MaterialSource,
    timing: MaterialTiming,
}

impl AutoBindingScenario {
    pub(super) const SESSION_SECRET_PRELOADED: Self = Self {
        source: MaterialSource::SessionSecret,
        timing: MaterialTiming::Preloaded,
    };

    pub(super) const SESSION_SECRET_REFRESH: Self = Self {
        source: MaterialSource::SessionSecret,
        timing: MaterialTiming::RefreshAfterHandshake,
    };

    pub(super) const KEY_LOG_PRELOADED: Self = Self {
        source: MaterialSource::KeyLog,
        timing: MaterialTiming::Preloaded,
    };

    pub(super) const KEY_LOG_REFRESH: Self = Self {
        source: MaterialSource::KeyLog,
        timing: MaterialTiming::RefreshAfterHandshake,
    };

    pub(super) fn display_name(self) -> String {
        format!(
            "{} {}",
            self.source.display_name(),
            self.timing.display_name()
        )
    }

    pub(super) fn config_version(self) -> String {
        format!(
            "e2e-tls-material-{}-{}",
            self.source.config_name(),
            self.timing.config_name()
        )
    }

    pub(super) fn temp_root_prefix(self) -> String {
        format!(
            "{}-{}",
            self.source.temp_root_prefix(),
            self.timing.temp_root_suffix()
        )
    }

    pub(super) fn material_file_name(self) -> &'static str {
        self.source.material_file_name()
    }

    pub(super) fn write_initial_material(
        self,
        path: &Path,
        fixture: SyntheticTls13AutoBindingFixture,
    ) -> io::Result<()> {
        self.timing.write_initial(self.source, path, fixture)
    }

    pub(super) fn material_refresh(self) -> Option<MaterialRefresh> {
        self.timing.material_refresh(self.source)
    }

    pub(super) fn configure_material(self, config: &mut AgentConfig, material_path: &Path) {
        let material = self.source.material_config(material_path);
        config.tls.materials.push(material);
        self.source.push_decrypt_hint_ref(config);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterialSource {
    SessionSecret,
    KeyLog,
}

impl MaterialSource {
    fn display_name(self) -> &'static str {
        match self {
            Self::SessionSecret => "session-secret",
            Self::KeyLog => "keylog",
        }
    }

    fn config_name(self) -> &'static str {
        match self {
            Self::SessionSecret => "session-secret",
            Self::KeyLog => "keylog",
        }
    }

    fn temp_root_prefix(self) -> &'static str {
        match self {
            Self::SessionSecret => "tls-sess",
            Self::KeyLog => "tls-keylog",
        }
    }

    fn material_file_name(self) -> &'static str {
        match self {
            Self::SessionSecret => "session-secrets.jsonl",
            Self::KeyLog => "sslkeylog.log",
        }
    }

    fn material_config(self, material_path: &Path) -> TlsMaterialConfig {
        TlsMaterialConfig {
            id: Some(self.id().to_string()),
            kind: self.kind(),
            path: material_path.to_path_buf(),
        }
    }

    fn push_decrypt_hint_ref(self, config: &mut AgentConfig) {
        match self {
            Self::SessionSecret => config
                .tls
                .plaintext
                .decrypt_hints
                .session_secret_refs
                .push(SESSION_SECRET_ID.to_string()),
            Self::KeyLog => config
                .tls
                .plaintext
                .decrypt_hints
                .key_log_refs
                .push(KEY_LOG_ID.to_string()),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::SessionSecret => SESSION_SECRET_ID,
            Self::KeyLog => KEY_LOG_ID,
        }
    }

    fn kind(self) -> TlsMaterialKind {
        match self {
            Self::SessionSecret => TlsMaterialKind::SessionSecretFile,
            Self::KeyLog => TlsMaterialKind::KeyLogFile,
        }
    }

    fn write_complete_material(
        self,
        path: &Path,
        fixture: SyntheticTls13AutoBindingFixture,
    ) -> io::Result<()> {
        match self {
            Self::SessionSecret => {
                write_file_atomically(path, fixture.session_secret_material_jsonl().as_bytes())
            }
            Self::KeyLog => write_file_atomically(path, fixture.key_log_material().as_bytes()),
        }
    }

    fn write_pending_material(
        self,
        path: &Path,
        fixture: SyntheticTls13AutoBindingFixture,
    ) -> io::Result<()> {
        match self {
            Self::SessionSecret => write_file_atomically(path, b"\n"),
            Self::KeyLog => {
                write_file_atomically(path, fixture.partial_key_log_material().as_bytes())
            }
        }
    }

    fn refresh_action(self) -> MaterialRefresh {
        match self {
            Self::SessionSecret => MaterialRefresh::ReplaceSessionSecretFile,
            Self::KeyLog => MaterialRefresh::CompleteKeyLogLine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterialTiming {
    Preloaded,
    RefreshAfterHandshake,
}

impl MaterialTiming {
    fn display_name(self) -> &'static str {
        match self {
            Self::Preloaded => "auto-binding",
            Self::RefreshAfterHandshake => "material-refresh-auto-binding",
        }
    }

    fn config_name(self) -> &'static str {
        match self {
            Self::Preloaded => "auto-binding",
            Self::RefreshAfterHandshake => "material-refresh-auto-binding",
        }
    }

    fn temp_root_suffix(self) -> &'static str {
        match self {
            Self::Preloaded => "auto",
            Self::RefreshAfterHandshake => "refresh",
        }
    }

    fn write_initial(
        self,
        source: MaterialSource,
        path: &Path,
        fixture: SyntheticTls13AutoBindingFixture,
    ) -> io::Result<()> {
        match self {
            Self::Preloaded => source.write_complete_material(path, fixture),
            Self::RefreshAfterHandshake => source.write_pending_material(path, fixture),
        }
    }

    fn material_refresh(self, source: MaterialSource) -> Option<MaterialRefresh> {
        match self {
            Self::Preloaded => None,
            Self::RefreshAfterHandshake => Some(source.refresh_action()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MaterialRefresh {
    ReplaceSessionSecretFile,
    CompleteKeyLogLine,
}

impl MaterialRefresh {
    pub(super) fn apply(
        self,
        path: &Path,
        fixture: SyntheticTls13AutoBindingFixture,
    ) -> io::Result<()> {
        match self {
            Self::ReplaceSessionSecretFile => {
                write_file_atomically(path, fixture.session_secret_material_jsonl().as_bytes())
            }
            Self::CompleteKeyLogLine => {
                let mut file = fs::OpenOptions::new().append(true).open(path)?;
                file.write_all(fixture.key_log_material_tail().as_bytes())?;
                file.sync_all()
            }
        }
    }
}

fn write_file_atomically(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "tls-auto-binding-material".into());
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    fs::rename(temp_path, path)
}
