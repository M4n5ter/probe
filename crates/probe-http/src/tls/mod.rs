use rustls::{RootCertStore, pki_types::CertificateDer};

pub fn root_cert_store_with_native_roots(
    native_roots: Vec<CertificateDer<'static>>,
) -> Result<RootCertStore, rustls::Error> {
    let mut roots = RootCertStore::empty();
    for certificate in native_roots {
        roots.add(certificate)?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_store_allows_empty_native_roots() {
        let roots = root_cert_store_with_native_roots(Vec::new())
            .expect("empty native roots should still build a root store");

        assert!(roots.is_empty());
    }
}
