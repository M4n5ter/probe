use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use probe_config::{
    AgentConfig, EnforcementPolicyManifest, EnforcementPolicySourceConfig, ExporterTransportConfig,
    TlsMaterialKind, TransparentInterceptionMitmPlaintextBridgeModeConfig,
};
use rustix::fs::OFlags;

use crate::configured_enforcement::validate_enforcement_policy_manifest;

use super::{
    config_edit::{TuiError, sync_directory},
    local_profile::LocalProbeProfile,
};

const MITM_CA_CERTIFICATE_ID: &str = "mitm-ca";
const MITM_CA_PRIVATE_KEY_ID: &str = "mitm-ca-key";

pub(super) fn ensure_generated_local_paths(
    config: &AgentConfig,
    profile: &LocalProbeProfile,
) -> Result<(), TuiError> {
    ensure_generated_file_export_dirs(config, &profile.export_file)?;
    ensure_generated_admin_socket_dir(config, &profile.admin_socket)?;
    ensure_generated_enforcement_policy_manifest(config, &profile.mitm.enforcement_policy_file)?;
    ensure_generated_mitm_feed_dir(config, &profile.mitm.plaintext_feed)?;
    ensure_generated_mitm_ca_materials(config, profile)
}

fn ensure_generated_file_export_dirs(
    config: &AgentConfig,
    default_export_file: &Path,
) -> Result<(), TuiError> {
    let needs_default_export_dir = config.exporters.iter().any(|exporter| {
        matches!(
            &exporter.transport,
            ExporterTransportConfig::File { path } if path == default_export_file
        )
    });
    if !needs_default_export_dir {
        return Ok(());
    }
    let Some(parent) = default_export_file.parent() else {
        return Ok(());
    };
    ensure_private_directory(parent)
}

fn ensure_generated_admin_socket_dir(
    config: &AgentConfig,
    default_admin_socket: &Path,
) -> Result<(), TuiError> {
    if !config.admin.enabled || config.admin.socket_path != default_admin_socket {
        return Ok(());
    }
    let Some(parent) = default_admin_socket.parent() else {
        return Ok(());
    };
    ensure_private_directory(parent)
}

fn ensure_generated_enforcement_policy_manifest(
    config: &AgentConfig,
    default_policy_file: &Path,
) -> Result<(), TuiError> {
    let EnforcementPolicySourceConfig::File { path } = &config.enforcement.policy.source else {
        return Ok(());
    };
    if path != default_policy_file {
        return Ok(());
    }
    let source = default_enforcement_policy_manifest_source()?;
    ensure_generated_policy_manifest_file(default_policy_file, &source)
}

fn default_enforcement_policy_manifest_source() -> Result<String, TuiError> {
    let manifest = EnforcementPolicyManifest {
        id: "local-default".to_string(),
        version: "local".to_string(),
        ..EnforcementPolicyManifest::default()
    };
    toml::to_string_pretty(&manifest).map_err(TuiError::SerializeRuntimeConfig)
}

fn ensure_generated_mitm_feed_dir(
    config: &AgentConfig,
    default_feed: &Path,
) -> Result<(), TuiError> {
    let mitm = &config.enforcement.interception.mitm;
    if mitm.plaintext_bridge.mode
        != TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed
        || mitm.plaintext_bridge.path.as_deref() != Some(default_feed)
    {
        return Ok(());
    }
    let Some(parent) = default_feed.parent() else {
        return Ok(());
    };
    ensure_private_directory(parent)
}

fn ensure_generated_mitm_ca_materials(
    config: &AgentConfig,
    profile: &LocalProbeProfile,
) -> Result<(), TuiError> {
    let Some(certificate_path) = configured_tls_material_path(
        config,
        MITM_CA_CERTIFICATE_ID,
        TlsMaterialKind::MitmCaCertificate,
    ) else {
        return Ok(());
    };
    let Some(private_key_path) = configured_tls_material_path(
        config,
        MITM_CA_PRIVATE_KEY_ID,
        TlsMaterialKind::MitmCaPrivateKey,
    ) else {
        return Ok(());
    };
    if certificate_path != profile.mitm.ca_certificate
        || private_key_path != profile.mitm.ca_private_key
    {
        return Ok(());
    }
    let parent = shared_parent(certificate_path, private_key_path)?;
    ensure_private_directory(parent)?;

    let certificate_exists = generated_regular_file_exists(certificate_path)?;
    let private_key_exists = generated_regular_file_exists(private_key_path)?;
    match (certificate_exists, private_key_exists) {
        (true, true) => harden_existing_generated_mitm_ca_pair(certificate_path, private_key_path),
        (false, false) => write_new_mitm_ca_pair(certificate_path, private_key_path),
        (true, false) | (false, true) => Err(incomplete_generated_mitm_ca_pair_error(
            certificate_path,
            private_key_path,
        )),
    }
}

fn configured_tls_material_path<'a>(
    config: &'a AgentConfig,
    id: &str,
    kind: TlsMaterialKind,
) -> Option<&'a Path> {
    let mitm = &config.enforcement.interception.mitm;
    let expected_ref = match kind {
        TlsMaterialKind::MitmCaCertificate => mitm.ca_certificate_ref.as_deref(),
        TlsMaterialKind::MitmCaPrivateKey => mitm.ca_private_key_ref.as_deref(),
        _ => None,
    };
    if expected_ref != Some(id) {
        return None;
    }
    config
        .tls
        .materials
        .iter()
        .find(|material| material.id.as_deref() == Some(id) && material.kind == kind)
        .map(|material| material.path.as_path())
}

fn write_new_mitm_ca_pair(
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<(), TuiError> {
    let (certificate, private_key) = generate_mitm_ca_material(certificate_path)?;
    write_generated_pair(
        certificate_path,
        certificate.as_bytes(),
        private_key_path,
        private_key.as_bytes(),
    )
}

fn generate_mitm_ca_material(error_path: &Path) -> Result<(String, String), TuiError> {
    let signing_key =
        rcgen::KeyPair::generate().map_err(|error| mitm_ca_generation_error(error_path, error))?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Traffic Probe Local MITM CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let certificate = params
        .self_signed(&signing_key)
        .map_err(|error| mitm_ca_generation_error(error_path, error))?;
    Ok((certificate.pem(), signing_key.serialize_pem()))
}

fn mitm_ca_generation_error(path: &Path, error: rcgen::Error) -> TuiError {
    TuiError::WriteConfig {
        path: path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .display()
            .to_string(),
        source: std::io::Error::other(format!("failed to generate MITM CA material: {error}")),
    }
}

fn write_generated_pair(
    first_path: &Path,
    first_contents: &[u8],
    second_path: &Path,
    second_contents: &[u8],
) -> Result<(), TuiError> {
    let parent = shared_parent(first_path, second_path)?;
    ensure_private_directory(parent)?;
    let (first_temp_path, first_temp_file) = create_generated_temp_file(parent, first_path)?;
    let (second_temp_path, second_temp_file) = create_generated_temp_file(parent, second_path)?;

    let write_result = write_temp_file(&first_temp_path, first_temp_file, first_contents)
        .and_then(|()| write_temp_file(&second_temp_path, second_temp_file, second_contents))
        .and_then(|()| rename_synced(&second_temp_path, second_path))
        .and_then(|()| rename_synced(&first_temp_path, first_path))
        .and_then(|()| sync_directory(parent));
    if write_result.is_err() {
        let _ = fs::remove_file(&first_temp_path);
        let _ = fs::remove_file(&second_temp_path);
    }
    write_result
}

fn write_generated_file(path: &Path, contents: &[u8]) -> Result<(), TuiError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_directory(parent)?;
    let (temp_path, temp_file) = create_generated_temp_file(parent, path)?;
    let write_result = write_temp_file(&temp_path, temp_file, contents)
        .and_then(|()| rename_synced(&temp_path, path))
        .and_then(|()| sync_directory(parent));
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn shared_parent<'a>(first_path: &'a Path, second_path: &'a Path) -> Result<&'a Path, TuiError> {
    let first_parent = first_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let second_parent = second_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if first_parent != second_parent {
        return Err(TuiError::WriteConfig {
            path: first_parent.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "generated MITM CA certificate and private key must share a directory",
            ),
        });
    }
    Ok(first_parent)
}

fn create_generated_temp_file(
    parent: &Path,
    final_path: &Path,
) -> Result<(PathBuf, File), TuiError> {
    let file_name = final_path
        .file_name()
        .ok_or_else(|| TuiError::InvalidConfigPath(final_path.display().to_string()))?
        .to_string_lossy();
    for attempt in 0..100 {
        let candidate = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(TuiError::WriteConfig {
                    path: candidate.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(TuiError::InvalidConfigPath(format!(
        "could not allocate generated temp file beside {}",
        final_path.display()
    )))
}

fn generated_regular_file_exists(path: &Path) -> Result<bool, TuiError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(TuiError::WriteConfig {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "generated path must be a real regular file",
                ),
            })
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn harden_existing_generated_mitm_ca_pair(
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<(), TuiError> {
    harden_existing_generated_file(certificate_path)?;
    harden_existing_generated_file(private_key_path)
}

fn harden_existing_generated_file(path: &Path) -> Result<(), TuiError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| TuiError::WriteConfig {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(TuiError::WriteConfig {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "generated path must be a real regular file",
            ),
        });
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.sync_all())
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })
}

fn incomplete_generated_mitm_ca_pair_error(
    certificate_path: &Path,
    private_key_path: &Path,
) -> TuiError {
    TuiError::WriteConfig {
        path: certificate_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .display()
            .to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "generated MITM CA material pair is incomplete; restore or remove both {} and {}",
                certificate_path.display(),
                private_key_path.display()
            ),
        ),
    }
}

fn ensure_generated_policy_manifest_file(path: &Path, source: &str) -> Result<(), TuiError> {
    if generated_regular_file_exists(path)? && generated_policy_manifest_is_valid(path)? {
        return Ok(());
    }
    write_generated_file(path, source.as_bytes())
}

fn generated_policy_manifest_is_valid(path: &Path) -> Result<bool, TuiError> {
    let source = fs::read_to_string(path).map_err(|source| TuiError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    Ok(toml::from_str::<EnforcementPolicyManifest>(&source)
        .ok()
        .and_then(|manifest| validate_enforcement_policy_manifest(manifest).ok())
        .is_some())
}

fn write_temp_file(path: &Path, mut file: File, bytes: &[u8]) -> Result<(), TuiError> {
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })
}

fn rename_synced(from: &Path, to: &Path) -> Result<(), TuiError> {
    fs::rename(from, to).map_err(|source| TuiError::WriteConfig {
        path: to.display().to_string(),
        source,
    })
}

pub(super) fn ensure_private_directory(path: &Path) -> Result<(), TuiError> {
    fs::create_dir_all(path).map_err(|source| TuiError::WriteConfig {
        path: path.display().to_string(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| TuiError::WriteConfig {
        path: path.display().to_string(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TuiError::WriteConfig {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "generated path must be a real directory",
            ),
        });
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use exporter::FileExporter;
    use probe_config::{ExporterConfig, TlsMaterialConfig, TransparentInterceptionStrategyConfig};
    use tempfile::TempDir;

    use super::super::local_profile::LocalMitmProfile;
    use super::*;

    #[test]
    fn generated_default_file_exporter_parent_is_created() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = TempDir::new()?;
        let export_file = temp.path().join("export").join("events.jsonl");
        let mut config = AgentConfig::default();
        config.exporters.push(ExporterConfig {
            transport: ExporterTransportConfig::File {
                path: export_file.clone(),
            },
            ..ExporterConfig::default()
        });

        ensure_generated_file_export_dirs(&config, &export_file)?;

        assert_private_directory(export_file.parent().expect("export parent"))?;
        FileExporter::preflight_path(&export_file)?;
        Ok(())
    }

    #[test]
    fn generated_mitm_feed_parent_is_created() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        configure_managed_mitm_resources(&mut config, &profile.mitm);

        ensure_generated_local_paths(&config, &profile)?;

        assert_private_directory(profile.mitm.plaintext_feed.parent().expect("feed parent"))?;
        Ok(())
    }

    #[test]
    fn generated_policy_manifest_repairs_malformed_managed_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: profile.mitm.enforcement_policy_file.clone(),
        };
        ensure_private_directory(
            profile
                .mitm
                .enforcement_policy_file
                .parent()
                .expect("policy parent"),
        )?;
        fs::write(&profile.mitm.enforcement_policy_file, "partial")?;

        ensure_generated_local_paths(&config, &profile)?;

        let repaired = fs::read_to_string(&profile.mitm.enforcement_policy_file)?;
        let manifest = toml::from_str::<EnforcementPolicyManifest>(&repaired)?;
        assert_eq!(manifest.id, "local-default");
        assert_ne!(repaired, "partial");
        Ok(())
    }

    #[test]
    fn generated_policy_manifest_repairs_empty_managed_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: profile.mitm.enforcement_policy_file.clone(),
        };
        ensure_private_directory(
            profile
                .mitm
                .enforcement_policy_file
                .parent()
                .expect("policy parent"),
        )?;
        fs::write(&profile.mitm.enforcement_policy_file, "")?;

        ensure_generated_local_paths(&config, &profile)?;

        let repaired = fs::read_to_string(&profile.mitm.enforcement_policy_file)?;
        let manifest = toml::from_str::<EnforcementPolicyManifest>(&repaired)?;
        assert_eq!(manifest.id, "local-default");
        assert_ne!(repaired, "");
        Ok(())
    }

    #[test]
    fn generated_mitm_ca_pair_is_created() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        configure_managed_mitm_resources(&mut config, &profile.mitm);

        ensure_generated_local_paths(&config, &profile)?;

        assert!(profile.mitm.ca_certificate.is_file());
        assert!(profile.mitm.ca_private_key.is_file());
        assert_private_directory(profile.mitm.ca_certificate.parent().expect("tls parent"))?;
        assert_eq!(
            fs::metadata(&profile.mitm.ca_certificate)?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&profile.mitm.ca_private_key)?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn existing_generated_mitm_ca_pair_is_hardened() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        configure_managed_mitm_resources(&mut config, &profile.mitm);
        let tls_parent = profile.mitm.ca_certificate.parent().expect("tls parent");
        fs::create_dir_all(tls_parent)?;
        fs::set_permissions(tls_parent, fs::Permissions::from_mode(0o755))?;
        fs::write(&profile.mitm.ca_certificate, "existing certificate\n")?;
        fs::write(&profile.mitm.ca_private_key, "existing private key\n")?;
        fs::set_permissions(
            &profile.mitm.ca_certificate,
            fs::Permissions::from_mode(0o644),
        )?;
        fs::set_permissions(
            &profile.mitm.ca_private_key,
            fs::Permissions::from_mode(0o644),
        )?;

        ensure_generated_local_paths(&config, &profile)?;

        assert_private_directory(tls_parent)?;
        assert_eq!(
            fs::read_to_string(&profile.mitm.ca_certificate)?,
            "existing certificate\n"
        );
        assert_eq!(
            fs::read_to_string(&profile.mitm.ca_private_key)?,
            "existing private key\n"
        );
        assert_eq!(
            fs::metadata(&profile.mitm.ca_certificate)?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&profile.mitm.ca_private_key)?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn incomplete_generated_mitm_ca_pair_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        configure_managed_mitm_resources(&mut config, &profile.mitm);
        ensure_private_directory(profile.mitm.ca_certificate.parent().expect("tls parent"))?;
        fs::write(&profile.mitm.ca_certificate, "partial\n")?;

        let error = ensure_generated_local_paths(&config, &profile)
            .expect_err("incomplete generated CA material pair must not be silently rotated");

        assert!(
            error
                .to_string()
                .contains("generated MITM CA material pair is incomplete")
        );
        assert_eq!(
            fs::read_to_string(&profile.mitm.ca_certificate)?,
            "partial\n"
        );
        assert!(!profile.mitm.ca_private_key.exists());
        Ok(())
    }

    #[test]
    fn generated_paths_do_not_run_for_non_mitm_interception()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let profile = LocalProbeProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;

        ensure_generated_local_paths(&config, &profile)?;

        assert!(
            !profile
                .mitm
                .plaintext_feed
                .parent()
                .expect("feed parent")
                .exists()
        );
        assert!(!profile.mitm.ca_certificate.exists());
        Ok(())
    }

    fn assert_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        assert!(path.is_dir());
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    fn configure_managed_mitm_resources(config: &mut AgentConfig, profile: &LocalMitmProfile) {
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: profile.enforcement_policy_file.clone(),
        };
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path =
            Some(profile.plaintext_feed.clone());
        config.enforcement.interception.mitm.ca_certificate_ref =
            Some(MITM_CA_CERTIFICATE_ID.to_string());
        config.enforcement.interception.mitm.ca_private_key_ref =
            Some(MITM_CA_PRIVATE_KEY_ID.to_string());
        config.tls.materials.push(TlsMaterialConfig {
            id: Some(MITM_CA_CERTIFICATE_ID.to_string()),
            kind: TlsMaterialKind::MitmCaCertificate,
            path: profile.ca_certificate.clone(),
        });
        config.tls.materials.push(TlsMaterialConfig {
            id: Some(MITM_CA_PRIVATE_KEY_ID.to_string()),
            kind: TlsMaterialKind::MitmCaPrivateKey,
            path: profile.ca_private_key.clone(),
        });
    }
}
