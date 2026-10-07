use std::env;
use std::fmt::{Display, Formatter};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use itertools::Itertools;
use reqwest::{Certificate, Identity};
use rustls_native_certs::{CertificateResult, load_certs_from_paths};
use rustls_pki_types::CertificateDer;
use tracing::{debug, warn};
use webpki::{Error as WebPkiError, anchor_from_trusted_cert};
use x509_parser::prelude::{FromDer, X509Certificate};

use uv_fs::Simplified;
use uv_static::EnvVars;
use uv_warnings::warn_user_once;

#[derive(Debug, Clone)]
enum CertificateSource {
    CertFileArg(PathBuf),
    SslCertFile(PathBuf),
    SslCertDir(PathBuf),
}

impl CertificateSource {
    const fn description(&self) -> &'static str {
        match self {
            Self::CertFileArg(_) => "--cert",
            Self::SslCertFile(_) => EnvVars::SSL_CERT_FILE,
            Self::SslCertDir(_) => EnvVars::SSL_CERT_DIR,
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::CertFileArg(path) | Self::SslCertFile(path) | Self::SslCertDir(path) => path,
        }
    }
}

#[derive(Debug, Clone)]
struct DiagnosticCertificate(CertificateDer<'static>);

impl DiagnosticCertificate {
    fn parse(&self) -> Option<X509Certificate<'_>> {
        match X509Certificate::from_der(self.0.as_ref()) {
            Ok((_, certificate)) => Some(certificate),
            Err(err) => {
                debug!("Failed to parse certificate for improved validation message: {err:?}");
                None
            }
        }
    }
}

#[derive(Debug)]
struct InvalidCertificateWarning {
    source: CertificateSource,
    certificate: DiagnosticCertificate,
    reason: InvalidCertificateReason,
}

#[derive(Debug)]
enum InvalidCertificateReason {
    UnsupportedCriticalExtension,
    BadDer,
    BadDerTime,
    EmptyEkuExtension,
    ExtensionValueInvalid,
    MalformedExtensions,
    TrailingData,
    UnsupportedCertVersion,
    Other(WebPkiError),
}

impl InvalidCertificateReason {
    fn from_webpki_error(error: WebPkiError) -> Self {
        match error {
            WebPkiError::UnsupportedCriticalExtension => Self::UnsupportedCriticalExtension,
            WebPkiError::BadDer => Self::BadDer,
            WebPkiError::BadDerTime => Self::BadDerTime,
            WebPkiError::EmptyEkuExtension => Self::EmptyEkuExtension,
            WebPkiError::ExtensionValueInvalid => Self::ExtensionValueInvalid,
            WebPkiError::MalformedExtensions => Self::MalformedExtensions,
            WebPkiError::TrailingData(_) => Self::TrailingData,
            WebPkiError::UnsupportedCertVersion => Self::UnsupportedCertVersion,
            error => Self::Other(error),
        }
    }

    fn message(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedCriticalExtension => None,
            Self::BadDer => Some("malformed DER certificate"),
            Self::BadDerTime => Some("malformed certificate time"),
            Self::EmptyEkuExtension => Some("empty extended key usage extension"),
            Self::ExtensionValueInvalid => Some("invalid certificate extension value"),
            Self::MalformedExtensions => Some("malformed certificate extensions"),
            Self::TrailingData => Some("trailing data in DER certificate"),
            Self::UnsupportedCertVersion => Some("unsupported certificate version"),
            Self::Other(_) => None,
        }
    }
}

impl InvalidCertificateWarning {
    fn new(source: CertificateSource, cert: &CertificateDer<'_>, error: WebPkiError) -> Self {
        Self {
            source,
            certificate: DiagnosticCertificate(cert.clone().into_owned()),
            reason: InvalidCertificateReason::from_webpki_error(error),
        }
    }
}

fn format_invalid_certificate_detail(
    reason: &InvalidCertificateReason,
    certificate: Option<&X509Certificate<'_>>,
) -> Option<String> {
    match reason {
        InvalidCertificateReason::UnsupportedCertVersion => certificate.map(|certificate| {
            format!(
                "unsupported certificate version `{}`",
                certificate.version()
            )
        }),
        InvalidCertificateReason::ExtensionValueInvalid => None,
        _ => None,
    }
}

impl Display for InvalidCertificateWarning {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "certificate in `{}` (from `{}`) ",
            self.source.path().simplified_display(),
            self.source.description()
        )?;
        match &self.reason {
            InvalidCertificateReason::UnsupportedCriticalExtension => {
                write!(f, "uses an unsupported critical extension")?;
            }
            _ => {
                write!(f, "could not be used as a trust anchor")?;
            }
        }

        let parsed_certificate = self.certificate.parse();
        if let Some(certificate) = parsed_certificate.as_ref() {
            let subject = certificate.subject();
            if subject.iter_attributes().next().is_some() {
                // Avoid rendering empty subject DNs.
                write!(f, " on certificate `{subject}`")?;
            }
            if let InvalidCertificateReason::UnsupportedCriticalExtension = &self.reason {
                let critical_extensions = certificate
                    .iter_extensions()
                    .filter(|extension| extension.critical)
                    .map(|extension| extension.oid.to_owned())
                    .collect::<Vec<_>>();
                if let [critical_extension] = critical_extensions.as_slice() {
                    write!(f, "; critical extension: `{critical_extension}`")?;
                } else if !critical_extensions.is_empty() {
                    write!(
                        f,
                        "; critical extensions: {}",
                        critical_extensions
                            .iter()
                            .map(|oid| format!("`{oid}`"))
                            .join(", ")
                    )?;
                }
            }
        }

        let detailed_reason =
            format_invalid_certificate_detail(&self.reason, parsed_certificate.as_ref())
                .or_else(|| self.reason.message().map(str::to_owned))
                .or_else(|| {
                    if let InvalidCertificateReason::Other(error) = &self.reason {
                        Some(format!("{error:?}"))
                    } else {
                        None
                    }
                });
        if let Some(detailed_reason) = detailed_reason {
            write!(f, ": {detailed_reason}")?;
        }

        Ok(())
    }
}

/// A collection of TLS certificates in DER form.
#[derive(Debug, Clone, Default)]
pub struct Certificates(Vec<CertificateDer<'static>>);

impl Certificates {
    /// Load the bundled Mozilla root certificates.
    ///
    /// We use `webpki-root-certs` because reqwest's [`ClientBuilder::tls_certs_only`] accepts
    /// [`Certificate`] values built from DER bytes.
    pub(crate) fn webpki_roots() -> Self {
        // Each [`CertificateDer`] in [`webpki_root_certs::TLS_SERVER_ROOT_CERTS`] borrows from static
        // data, so cloning into the [`Vec`] only copies the fat pointer, not the certificate bytes.
        Self(webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec())
    }

    /// Load a custom CA certificate bundle from an explicit path.
    ///
    /// Unlike [`Self::from_ssl_cert_file`], an invalid path or a bundle without any valid
    /// certificates returns an error instead of being ignored with a warning.
    pub fn from_file(file: &Path) -> Result<Self, CertificateFileError> {
        let metadata = file
            .metadata()
            .map_err(|err| CertificateFileError::Io(file.to_path_buf(), err))?;
        if !metadata.is_file() {
            return Err(CertificateFileError::NotFile(file.to_path_buf()));
        }

        let result = Self::from_paths(Some(file), None);
        for err in &result.errors {
            warn!(
                "Failed to load certificate file ({}): {err}",
                file.simplified_display()
            );
        }
        let certs =
            Self::from(result).filter_invalid(&CertificateSource::CertFileArg(file.to_path_buf()));
        if certs.0.is_empty() {
            return Err(CertificateFileError::NoValidCertificates(
                file.to_path_buf(),
            ));
        }
        Ok(certs)
    }

    /// Load custom CA certificates from `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables.
    ///
    /// Returns `None` if neither variable is set to a non-empty value. An explicitly configured
    /// file or directory always replaces the default certificate roots, even when it is missing,
    /// inaccessible, or contains no valid certificates. Delegates path loading to
    /// [`rustls_native_certs::load_certs_from_paths`].
    pub fn from_env() -> Option<Self> {
        let mut certs = Self::default();
        let mut has_source = false;

        if let Some(ssl_cert_file) = env::var_os(EnvVars::SSL_CERT_FILE)
            && !ssl_cert_file.is_empty()
        {
            has_source = true;
            if let Some(file_certs) = Self::from_ssl_cert_file(&ssl_cert_file) {
                certs.merge(file_certs);
            }
        }

        if let Some(ssl_cert_dir) = env::var_os(EnvVars::SSL_CERT_DIR)
            && !ssl_cert_dir.is_empty()
        {
            has_source = true;
            if let Some(dir_certs) = Self::from_ssl_cert_dir(&ssl_cert_dir) {
                certs.merge(dir_certs);
            }
        }

        if has_source { Some(certs) } else { None }
    }

    /// Load certificates from the value of `SSL_CERT_FILE`.
    ///
    /// Returns `None` if the value is empty, the path does not refer to an accessible file,
    /// or the file contains no valid certificates.
    fn from_ssl_cert_file(ssl_cert_file: &std::ffi::OsStr) -> Option<Self> {
        if ssl_cert_file.is_empty() {
            return None;
        }

        let file = PathBuf::from(ssl_cert_file);
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => {
                let result = Self::from_paths(Some(&file), None);
                for err in &result.errors {
                    warn_user_once!(
                        "Failed to load `SSL_CERT_FILE` ({}): {err}",
                        file.simplified_display().cyan()
                    );
                }
                let certs = Self::from(result)
                    .filter_invalid(&CertificateSource::SslCertFile(file.clone()));
                if certs.0.is_empty() {
                    warn_user_once!(
                        "No valid certificates found in `SSL_CERT_FILE`: {}. No default certificates will be trusted.",
                        file.simplified_display().cyan()
                    );
                    return None;
                }
                Some(certs)
            }
            Ok(_) => {
                warn_user_once!(
                    "Invalid `SSL_CERT_FILE`. Path is not a file: {}. No default certificates will be trusted.",
                    file.simplified_display().cyan()
                );
                None
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                warn_user_once!(
                    "Invalid `SSL_CERT_FILE`. Path does not exist: {}. No default certificates will be trusted.",
                    file.simplified_display().cyan()
                );
                None
            }
            Err(err) => {
                warn_user_once!(
                    "Invalid `SSL_CERT_FILE`. Path is not accessible: {} ({err}). No default certificates will be trusted.",
                    file.simplified_display().cyan()
                );
                None
            }
        }
    }

    /// Load certificates from the value of `SSL_CERT_DIR`.
    ///
    /// The value may include multiple entries, separated by a platform-specific delimiter (`:` on
    /// Unix, `;` on Windows).
    ///
    /// Returns `None` if the value is empty, no listed directories exist, or no valid
    /// certificates are found.
    fn from_ssl_cert_dir(ssl_cert_dir: &std::ffi::OsStr) -> Option<Self> {
        if ssl_cert_dir.is_empty() {
            return None;
        }

        let (existing, missing): (Vec<_>, Vec<_>) =
            env::split_paths(ssl_cert_dir).partition(|path| path.exists());

        if existing.is_empty() {
            let end_note = if missing.len() == 1 {
                "The directory does not exist"
            } else {
                "The entries do not exist"
            };
            warn_user_once!(
                "Invalid `SSL_CERT_DIR`. {end_note}: {}. No default certificates will be trusted.",
                missing
                    .iter()
                    .map(Simplified::simplified_display)
                    .join(", ")
                    .cyan()
            );
            return None;
        }

        if !missing.is_empty() {
            let end_note = if missing.len() == 1 {
                "The following directory does not exist:"
            } else {
                "The following entries do not exist:"
            };
            warn_user_once!(
                "Invalid entries in `SSL_CERT_DIR`. {end_note}: {}.",
                missing
                    .iter()
                    .map(Simplified::simplified_display)
                    .join(", ")
                    .cyan()
            );
        }

        let mut certs = Self::default();
        for dir in &existing {
            let result = Self::from_paths(None, Some(dir));
            for err in &result.errors {
                warn_user_once!(
                    "Failed to load `SSL_CERT_DIR` ({}): {err}",
                    dir.simplified_display().cyan()
                );
            }
            let dir_certs =
                Self::from(result).filter_invalid(&CertificateSource::SslCertDir(dir.clone()));
            if !dir_certs.0.is_empty() {
                certs.merge(dir_certs);
            }
        }

        if certs.0.is_empty() {
            // Unlike `SSL_CERT_FILE`, it's plausible for this to be intentionally set to an
            // empty directory that a user _could_ put certificates in.
            warn!(
                "No valid certificates found in `SSL_CERT_DIR`: {}. No default certificates will be trusted.",
                existing
                    .iter()
                    .map(Simplified::simplified_display)
                    .join(", ")
            );
            return None;
        }

        Some(certs)
    }

    /// Load certificates from explicit file and directory paths.
    fn from_paths(file: Option<&Path>, dir: Option<&Path>) -> CertificateResult {
        load_certs_from_paths(file, dir)
    }

    fn filter_invalid(mut self, source: &CertificateSource) -> Self {
        self.0.retain(|cert| {
            if let Err(error) = anchor_from_trusted_cert(cert) {
                let warning = InvalidCertificateWarning::new((*source).clone(), cert, error);
                warn!("Ignoring invalid certificate: {warning}");
                return false;
            }

            true
        });
        self
    }

    /// Remove duplicate certificates, sorting by DER bytes.
    fn dedup(&mut self) {
        self.0
            .sort_unstable_by(|left, right| left.as_ref().cmp(right.as_ref()));
        self.0.dedup();
    }

    /// Merge another set of certificates into this one.
    ///
    /// After merging, duplicates are removed.
    fn merge(&mut self, other: Self) {
        self.0.extend(other.0);
        self.dedup();
    }

    /// Convert certificates to reqwest [`Certificate`] objects.
    pub(crate) fn to_reqwest_certs(&self) -> Vec<Certificate> {
        self.0
            .iter()
            // `Certificate::from_der` returns a `Result` for backend compatibility, but these
            // certificates come from `rustls-native-certs` and are already validated DER certs.
            .filter_map(|cert| match Certificate::from_der(cert) {
                Ok(certificate) => Some(certificate),
                Err(err) => {
                    debug!("Failed to convert DER certificate to reqwest certificate: {err}");
                    None
                }
            })
            .collect()
    }

    /// Iterate over raw DER certificates.
    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = &CertificateDer<'static>> {
        self.0.iter()
    }
}

impl From<CertificateResult> for Certificates {
    fn from(result: CertificateResult) -> Self {
        Self(result.certs)
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum CertificateError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Reqwest(reqwest::Error),
    #[error(
        "`SSL_CLIENT_CERT` must contain a certificate chain and an unencrypted PKCS#8, PKCS#1 or SEC1 private key"
    )]
    InvalidIdentity,
    #[error("failed to parse `SSL_CLIENT_CERT`")]
    InvalidIdentityPem(#[from] pem::PemError),
    #[error("failed to parse the private key in `SSL_CLIENT_CERT`")]
    InvalidIdentityKey(#[source] openssl::error::ErrorStack),
}

#[derive(thiserror::Error, Debug)]
pub enum CertificateFileError {
    #[error("Failed to read certificate file `{}`", .0.simplified_display())]
    Io(PathBuf, #[source] io::Error),
    #[error("Certificate path is not a file: `{}`", .0.simplified_display())]
    NotFile(PathBuf),
    #[error("No valid certificates found in: `{}`", .0.simplified_display())]
    NoValidCertificates(PathBuf),
}

/// Return the `Identity` from the provided file.
pub(crate) fn read_identity(
    ssl_client_cert: &std::ffi::OsStr,
) -> Result<Identity, CertificateError> {
    let mut buf = Vec::new();
    fs_err::File::open(ssl_client_cert)?.read_to_end(&mut buf)?;
    // The OpenSSL-backed native-tls API accepts the certificate chain and key separately, while
    // uv's SSL_CLIENT_CERT format contains both in one file.
    let sections = pem::parse_many(buf)?;
    let certificates = sections
        .iter()
        .filter(|section| section.tag() == "CERTIFICATE")
        .map(pem::encode)
        .collect::<String>();
    // The same key formats the Rustls-backed client took: PKCS#8, PKCS#1 (RSA) and SEC1 (EC).
    // native-tls only takes PKCS#8, so the key is re-encoded through OpenSSL. Encrypted keys stay
    // unsupported, as before: an `ENCRYPTED PRIVATE KEY` block is not matched, and a legacy
    // `Proc-Type: 4,ENCRYPTED` block fails to decrypt with the empty passphrase the callback
    // supplies -- which also keeps OpenSSL from prompting for one on the terminal.
    let private_key = sections
        .iter()
        .find(|section| {
            matches!(
                section.tag(),
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
            )
        })
        .ok_or(CertificateError::InvalidIdentity)?;
    if certificates.is_empty() {
        return Err(CertificateError::InvalidIdentity);
    }
    let private_key = openssl::pkey::PKey::private_key_from_pem_callback(
        pem::encode(private_key).as_bytes(),
        |_| Ok(0),
    )
    .and_then(|key| key.private_key_to_pem_pkcs8())
    .map_err(CertificateError::InvalidIdentityKey)?;
    Identity::from_pkcs8_pem(certificates.as_bytes(), &private_key)
        .map_err(CertificateError::Reqwest)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn generate_cert_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        cert.cert.pem()
    }

    #[test]
    fn test_from_ssl_cert_file_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing_file = dir.path().join("missing.pem");

        let certs = Certificates::from_ssl_cert_file(missing_file.as_os_str());
        assert!(certs.is_none());
    }

    #[test]
    fn test_from_env_missing_ssl_cert_file_returns_empty_roots() {
        let dir = tempfile::tempdir().unwrap();
        let missing_file = dir.path().join("missing.pem");

        temp_env::with_vars(
            [
                (EnvVars::SSL_CERT_FILE, Some(missing_file.as_os_str())),
                (EnvVars::SSL_CERT_DIR, None),
            ],
            || {
                let certs = Certificates::from_env().expect("explicit file should override roots");
                assert_eq!(certs.iter().count(), 0);
            },
        );
    }

    #[test]
    fn test_from_ssl_cert_file_empty_value_returns_none() {
        let certs = Certificates::from_ssl_cert_file(OsString::new().as_os_str());
        assert!(certs.is_none());
    }

    #[test]
    fn test_from_ssl_cert_file_no_valid_certs_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("empty.pem");
        fs_err::write(&cert_path, "not a certificate").unwrap();

        let certs = Certificates::from_ssl_cert_file(cert_path.as_os_str());
        assert!(certs.is_none());
    }

    #[test]
    fn test_from_ssl_cert_dir_empty_value_returns_none() {
        let certs = Certificates::from_ssl_cert_dir(OsString::new().as_os_str());
        assert!(certs.is_none());
    }

    #[test]
    fn test_from_ssl_cert_dir_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing_dir = dir.path().join("missing-dir");
        let cert_dirs = std::env::join_paths([&missing_dir]).unwrap();

        let certs = Certificates::from_ssl_cert_dir(cert_dirs.as_os_str());
        assert!(certs.is_none());
    }

    #[test]
    fn test_from_ssl_cert_dir_empty_existing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cert_dirs = std::env::join_paths([dir.path()]).unwrap();

        let certs = Certificates::from_ssl_cert_dir(cert_dirs.as_os_str());
        assert!(certs.is_none());
    }

    #[test]
    fn test_from_env_empty_ssl_cert_dir_returns_empty_roots() {
        let dir = tempfile::tempdir().unwrap();

        temp_env::with_vars(
            [
                (EnvVars::SSL_CERT_FILE, None),
                (EnvVars::SSL_CERT_DIR, Some(dir.path().as_os_str())),
            ],
            || {
                let certs =
                    Certificates::from_env().expect("explicit directory should override roots");
                assert_eq!(certs.iter().count(), 0);
            },
        );
    }

    #[test]
    fn test_merge_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        fs_err::write(&cert_path, generate_cert_pem()).unwrap();

        let first = Certificates::from(Certificates::from_paths(Some(&cert_path), None));
        let second = Certificates::from(Certificates::from_paths(Some(&cert_path), None));

        let mut merged = first;
        merged.merge(second);

        assert_eq!(merged.iter().count(), 1);
    }

    #[test]
    fn test_webpki_roots_not_empty() {
        let certs = Certificates::webpki_roots();
        assert!(certs.iter().count() > 0);
    }

    /// A self-signed certificate for `key`, PEM-encoded.
    fn self_signed_cert_pem(key: &openssl::pkey::PKey<openssl::pkey::Private>) -> String {
        use openssl::{asn1::Asn1Time, hash::MessageDigest, x509::X509};

        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(key, MessageDigest::sha256()).unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    fn rsa_key() -> openssl::pkey::PKey<openssl::pkey::Private> {
        openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap()
    }

    fn ec_key() -> openssl::pkey::PKey<openssl::pkey::Private> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap()
    }

    /// Write `cert` followed by `key` to a file and read it back as an identity.
    fn read_identity_from(cert: &str, key: &[u8]) -> Result<Identity, CertificateError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.pem");
        let mut contents = cert.as_bytes().to_vec();
        contents.extend_from_slice(key);
        fs_err::write(&path, contents).unwrap();
        read_identity(path.as_os_str())
    }

    #[test]
    fn test_read_identity_pkcs8_key() {
        let key = rsa_key();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN PRIVATE KEY-----"));
        read_identity_from(&self_signed_cert_pem(&key), &pem).unwrap();
    }

    #[test]
    fn test_read_identity_pkcs1_rsa_key() {
        let key = rsa_key();
        let pem = key.rsa().unwrap().private_key_to_pem().unwrap();
        assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        read_identity_from(&self_signed_cert_pem(&key), &pem).unwrap();
    }

    #[test]
    fn test_read_identity_sec1_ec_key() {
        let key = ec_key();
        let pem = key.ec_key().unwrap().private_key_to_pem().unwrap();
        assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN EC PRIVATE KEY-----"));
        read_identity_from(&self_signed_cert_pem(&key), &pem).unwrap();
    }

    #[test]
    fn test_read_identity_key_before_certificate() {
        let key = ec_key();
        let pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        read_identity_from(&pem, self_signed_cert_pem(&key).as_bytes()).unwrap();
    }

    #[test]
    fn test_read_identity_rejects_encrypted_pkcs8_key() {
        let key = rsa_key();
        let pem = key
            .private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), b"secret")
            .unwrap();
        assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let err = read_identity_from(&self_signed_cert_pem(&key), &pem).unwrap_err();
        assert!(matches!(err, CertificateError::InvalidIdentity), "{err:?}");
    }

    #[test]
    fn test_read_identity_rejects_encrypted_pkcs1_key() {
        let key = rsa_key();
        let pem = key
            .rsa()
            .unwrap()
            .private_key_to_pem_passphrase(openssl::symm::Cipher::aes_256_cbc(), b"secret")
            .unwrap();
        assert!(String::from_utf8_lossy(&pem).contains("Proc-Type: 4,ENCRYPTED"));
        // Must fail rather than prompt for a passphrase.
        let err = read_identity_from(&self_signed_cert_pem(&key), &pem).unwrap_err();
        assert!(
            matches!(err, CertificateError::InvalidIdentityKey(_)),
            "{err:?}"
        );
    }

    #[test]
    fn test_read_identity_rejects_missing_key() {
        let key = rsa_key();
        let err = read_identity_from(&self_signed_cert_pem(&key), b"").unwrap_err();
        assert!(matches!(err, CertificateError::InvalidIdentity), "{err:?}");
    }

    #[test]
    fn test_read_identity_rejects_missing_certificate() {
        let key = rsa_key();
        let pem = key.rsa().unwrap().private_key_to_pem().unwrap();
        let err = read_identity_from("", &pem).unwrap_err();
        assert!(matches!(err, CertificateError::InvalidIdentity), "{err:?}");
    }
}
