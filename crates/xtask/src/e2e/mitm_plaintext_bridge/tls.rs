use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) const SERVER_NAME: &str = "mitm-bridge.e2e.test";

pub(super) struct MitmCaMaterial {
    pub(super) certificate_path: PathBuf,
    pub(super) private_key_path: PathBuf,
}

pub(super) fn write_mitm_ca(root: &Path) -> Result<MitmCaMaterial, Box<dyn std::error::Error>> {
    let signing_key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let certificate = params.self_signed(&signing_key)?;
    let certificate_path = root.join("mitm-ca.pem");
    let private_key_path = root.join("mitm-ca.key");
    fs::write(&certificate_path, certificate.pem())?;
    fs::write(&private_key_path, signing_key.serialize_pem())?;
    Ok(MitmCaMaterial {
        certificate_path,
        private_key_path,
    })
}
