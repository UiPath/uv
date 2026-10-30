use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(feature = "blake2b")]
use blake2::Digest as _;
#[cfg(feature = "blake2b")]
use blake2::digest::consts::U32;
use openssl::hash::MessageDigest;
use tokio::io::{AsyncReadExt, ReadBuf};

use uv_pypi_types::{Digest, HashAlgorithm, HashDigest};

/// A [`HashAlgorithm`] this build cannot compute.
///
/// Digests come from the system OpenSSL, so which algorithms exist is a property of the providers
/// that library has loaded rather than of uv. Under a FIPS provider, MD5 is not among them and
/// `Hasher::try_from` fails here rather than silently falling back to a private implementation.
#[derive(Debug, thiserror::Error)]
pub enum HasherError {
    #[error(
        "Cannot compute a `{0}` hash: the system OpenSSL does not offer that digest. Under a FIPS \
         provider only approved algorithms are available; re-pin the requirement on a `sha256`, \
         `sha384` or `sha512` hash."
    )]
    Unavailable(&'static str, #[source] openssl::error::ErrorStack),
    #[error(
        "Cannot compute a `{0}` hash: this build of uv was compiled without it. Re-pin the \
         requirement on a `sha256`, `sha384` or `sha512` hash."
    )]
    Unsupported(&'static str),
}

/// A streaming hasher for a single [`HashAlgorithm`].
///
/// MD5 and SHA-2 are computed by the system OpenSSL, one variant per algorithm so that each
/// finalizes into the digest length its [`HashDigest`] variant holds.
pub enum Hasher {
    Md5(openssl::hash::Hasher),
    Sha256(openssl::hash::Hasher),
    Sha384(openssl::hash::Hasher),
    Sha512(openssl::hash::Hasher),
    /// BLAKE2b-256, which OpenSSL cannot supply.
    ///
    /// OpenSSL 3.0 offers only a fixed-length `BLAKE2B-512`; the `size` parameter that would yield
    /// a 256-bit digest arrived in 3.2, and BLAKE2b-256 is not a truncation of BLAKE2b-512 because
    /// the output length is part of the parameter block. So this one variant stays on the `blake2`
    /// crate, and a build without the `blake2b` feature compiles it out entirely rather than
    /// shipping crypto it cannot attribute to the validated module.
    #[cfg(feature = "blake2b")]
    Blake2b256(blake2::Blake2b<U32>),
}

impl std::fmt::Debug for Hasher {
    // Hand-written because `openssl::hash::Hasher` implements no `Debug`; the algorithm is the only
    // part worth printing anyway.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Hasher")
            .field(&self.algorithm().as_str())
            .finish()
    }
}

impl Hasher {
    fn algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Md5(_) => HashAlgorithm::Md5,
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha384(_) => HashAlgorithm::Sha384,
            Self::Sha512(_) => HashAlgorithm::Sha512,
            #[cfg(feature = "blake2b")]
            Self::Blake2b256(_) => HashAlgorithm::Blake2b256,
        }
    }

    /// Update the hash with the given bytes.
    pub fn update(&mut self, data: &[u8]) -> Result<(), openssl::error::ErrorStack> {
        match self {
            Self::Md5(hasher)
            | Self::Sha256(hasher)
            | Self::Sha384(hasher)
            | Self::Sha512(hasher) => hasher.update(data),
            #[cfg(feature = "blake2b")]
            Self::Blake2b256(hasher) => {
                hasher.update(data);
                Ok(())
            }
        }
    }
}

impl TryFrom<HashAlgorithm> for Hasher {
    type Error = HasherError;

    fn try_from(algorithm: HashAlgorithm) -> Result<Self, Self::Error> {
        let (digest, variant): (MessageDigest, fn(openssl::hash::Hasher) -> Self) = match algorithm
        {
            HashAlgorithm::Md5 => (MessageDigest::md5(), Self::Md5),
            HashAlgorithm::Sha256 => (MessageDigest::sha256(), Self::Sha256),
            HashAlgorithm::Sha384 => (MessageDigest::sha384(), Self::Sha384),
            HashAlgorithm::Sha512 => (MessageDigest::sha512(), Self::Sha512),
            HashAlgorithm::Blake2b256 => {
                #[cfg(feature = "blake2b")]
                {
                    return Ok(Self::Blake2b256(blake2::Blake2b::new()));
                }
                #[cfg(not(feature = "blake2b"))]
                {
                    return Err(HasherError::Unsupported(algorithm.as_str()));
                }
            }
        };

        // Where the provider policy actually applies: initialising the context performs the digest
        // fetch, so an algorithm the loaded providers do not offer fails here.
        let hasher = openssl::hash::Hasher::new(digest)
            .map_err(|err| HasherError::Unavailable(algorithm.as_str(), err))?;

        Ok(variant(hasher))
    }
}

impl From<Hasher> for HashDigest {
    fn from(hasher: Hasher) -> Self {
        match hasher {
            Hasher::Md5(hasher) => Self::Md5(finish(hasher)),
            Hasher::Sha256(hasher) => Self::Sha256(finish(hasher)),
            Hasher::Sha384(hasher) => Self::Sha384(finish(hasher)),
            Hasher::Sha512(hasher) => Self::Sha512(finish(hasher)),
            #[cfg(feature = "blake2b")]
            Hasher::Blake2b256(hasher) => {
                Self::Blake2b256(Digest::from_bytes(hasher.finalize().into()))
            }
        }
    }
}

/// Infallible in practice: the context was initialised successfully in `try_from`, so
/// `EVP_DigestFinal_ex` has nothing left to reject, and it returns the algorithm's own length.
/// Keeping the conversion infallible confines this change to the construction sites.
fn finish<const BYTES: usize>(mut hasher: openssl::hash::Hasher) -> Digest<BYTES> {
    let bytes = hasher
        .finish()
        .expect("OpenSSL failed to finalize an initialized digest");
    Digest::from_bytes(
        <[u8; BYTES]>::try_from(&*bytes).expect("OpenSSL returned a digest of another length"),
    )
}

pub struct HashReader<'a, R> {
    reader: R,
    hashers: &'a mut [Hasher],
    bytes_read: u64,
}

impl<'a, R> HashReader<'a, R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    pub fn new(reader: R, hashers: &'a mut [Hasher]) -> Self {
        HashReader {
            reader,
            hashers,
            bytes_read: 0,
        }
    }

    /// Return the number of bytes read from the underlying reader.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Exhaust the underlying reader.
    pub async fn finish(&mut self) -> Result<(), std::io::Error> {
        while self.read(&mut vec![0; 8192]).await? > 0 {}

        Ok(())
    }
}

impl<R> tokio::io::AsyncRead for HashReader<'_, R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let reader = Pin::new(&mut self.reader);
        let filled = buf.filled().len();
        match reader.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = &buf.filled()[filled..];
                self.bytes_read += bytes.len() as u64;
                for hasher in self.hashers.iter_mut() {
                    if let Err(err) = hasher.update(bytes) {
                        return Poll::Ready(Err(std::io::Error::other(err)));
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
