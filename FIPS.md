# FIPS behaviour of this uv fork

This fork routes uv's cryptography through the host's OpenSSL rather than
statically linked Rust implementations, so the cryptographic module decides what
is available. On a host configured for FIPS — Ubuntu Pro 24.04 with the
Canonical OpenSSL Cryptographic Module, running `3.0.13-0ubuntu3.15+Fips1` —
that means some things which work today stop working.

Uv needs **two build configurations**, because two RustCrypto dependencies
cannot be replaced by OpenSSL at all and can only be compiled out:

| build | cargo invocation | contains RustCrypto |
|---|---|---|
| ordinary | `cargo build --release -p uv` | yes — `blake2`, and reqsign's `sha1`/`hmac`/`rsa` |
| FIPS | `cargo build --release --no-default-features --features performance -p uv` | no |

The TLS transport and the SHA-2/MD5 hashing are the host's OpenSSL in **both**
configurations. The features only control what is additionally present.

## Behaviour that changes for existing code

### 1. An md5 hash fails in FIPS mode, in the modes that accept one

MD5 is not in the module, and under Ubuntu's FIPS configuration the default
provider is not loaded at all, so there is no fallback:

```
$ OPENSSL_FORCE_FIPS_MODE=1 openssl dgst -md5 </dev/null
Error setting digest
... inner_evp_generic_fetch:unsupported ... Algorithm (MD5 : 100)
```

uv computes a digest by constructing an `openssl::hash::Hasher`, which performs
that fetch, so where an md5 digest reaches the hasher it is refused by the
module rather than verified with uv's own implementation.

Be precise about where that is, because it is not `--require-hashes`. Upstream
uv already strips md5 digests in require mode (`HashStrategy`, gated on
`mode.is_require()`) and reports them as insecure, so md5 never reaches a hasher
there — that refusal is uv's own policy and predates this fork. What is affected
is **verify mode**: a `#md5=` URL fragment or a lockfile digest. Observed on the
same binary:

```
# providers not forced
uv pip install "six @ https://.../six-1.17.0-...whl#md5=090bac..."   # installs

# OPENSSL_FORCE_FIPS_MODE=1
uv pip install "six @ https://.../six-1.17.0-...whl#md5=090bac..."
  Cannot compute a `md5` hash: the system OpenSSL does not offer that digest.
```

Narrow either way: `HashPolicy::Generate` — the ordinary resolve and install
path — asks for SHA-256 only, so an index merely *advertising* an md5 digest
does not cause one to be computed.

The larger point is not behavioural. Routing MD5 through OpenSSL is what removes
the `md-5` crate from the binary, so there is no unvalidated MD5 implementation
present whether or not anything would have called it.

### 2. `--require-hashes` with a blake2b hash fails in the FIPS build

BLAKE2b is not an approved algorithm and OpenSSL refuses it in FIPS mode for the
same reason as MD5. It could not be moved to the module even in principle: uv
needs BLAKE2b-**256**, and OpenSSL 3.0 offers only a fixed-length
`BLAKE2B-512`. The `size` parameter that would yield a 256-bit digest arrived in
OpenSSL 3.2, and BLAKE2b-256 is not a truncation of BLAKE2b-512 — the output
length is part of the parameter block.

So it keeps its RustCrypto implementation behind the `blake2b` feature. The FIPS
build turns it off, which makes the crate absent rather than merely unused, and
`Hasher::try_from` reports that the build was compiled without it.

### 3. `uv publish` does not work in the FIPS build

PyPI's legacy upload form requires a blake2b digest of the uploaded file, so
with `blake2b` off there is nothing to put in the field and publishing fails.
There is no workaround short of enabling the feature.

### 4. S3, Azure Blob and GCS-hosted indexes are unavailable in the FIPS build

`UV_S3_ENDPOINT_URL`, `UV_AZURE_ENDPOINT_URL` and `UV_GCS_ENDPOINT_URL` are
honoured only when the `cloud-auth` feature is on. Requests to those endpoints
are otherwise unsigned, and authenticated buckets reject them.

### 5. The `SSL_CLIENT_CERT` key must be unencrypted

native-tls takes the certificate chain and the key separately, and only as
PKCS#8, so uv splits the file and re-encodes the key through OpenSSL. The key
formats the Rustls client took all still work: PKCS#8 (`PRIVATE KEY`), PKCS#1
(`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`). An encrypted key is rejected,
as it was upstream, with a message naming what the file must contain -- and
without OpenSSL prompting for a passphrase. Decrypt with
`openssl pkcs8 -topk8 -nocrypt`.

### 6. The keyring has no backend on Linux

The `secret-service` backend is gone from every configuration, not just the FIPS
one. It needs a DBus Secret Service, which a container does not have, so it
could not work there regardless; uv-keyring now falls back to its nop credential
builder. Credentials come from the environment, `.netrc`, the TOML store or the
index URL.

## What runs inside the module

- The TLS transport for every index and file-server request, via native-tls →
  the system libssl.
- SHA-256, SHA-384 and SHA-512 for package-integrity verification, wheel RECORD
  entries and the build backend's dist hashes.
- MD5, when the loaded providers offer it — that is, outside FIPS mode.
- The random bytes behind `uv_fastid::Id::secure`, which names cache archive and
  source-revision directories. `rand` stays in the graph through `retry-policies`, which
  uses it only to jitter retry delays.

## What is not in the module, by configuration

| crate | what for | ordinary | FIPS |
|---|---|---|---|
| `blake2` | BLAKE2b-256 pinned hashes | present | absent |
| `sha1`, `hmac` | reqsign request signing | present | absent |
| `rsa` | reqsign's Azure and Google signers | present | absent |
| `aes`, `pbkdf2`, `scrypt`, `pkcs5` | secret-service keyring | absent | absent |
| `sha2` | see below | present | present, unreachable |

`sha2` survives in the FIPS build through `cargo-util`, which exposes a `Sha256`
helper from a standalone module. `uv-git` imports `ProcessBuilder`,
`ProcessError` and `paths` from that crate and nothing else, none of which touch
it, and `cargo-util` has no feature to drop it — so removing it would mean
forking a crates.io crate to delete dead code. It is the one documented
exception, and it is asserted rather than assumed: the build checks that
`cargo-util` is the *only* crate depending on `sha2`, so a reachable one fails.

## Verifying a build

The dependency graph is the check that matters, because it is what an assessor
reads and what a future uv bump silently changes:

```sh
# Must print nothing.
cargo tree --locked -p uv --edges normal --no-default-features --features performance \
  | grep -E '(^|[[:space:]])(sha1|sha3|md-5|blake2|rsa|aes|hmac|pbkdf2|scrypt|pkcs5|secret-service) v'

# Must resolve to the system libssl, not a vendored or static copy.
ldd target/release/uv | grep -E 'lib(ssl|crypto)\.so\.3'
```

Then, on a FIPS host or with `OPENSSL_FORCE_FIPS_MODE=1`:

```sh
openssl list -providers    # expect `base` and `fips`, and no `default`
uv pip install --require-hashes -r reqs-sha256.txt   # succeeds
uv pip install --require-hashes -r reqs-md5.txt      # refused by the module
```

## What this fork does not address

uv's resolution and installation still trust whatever the index serves. Nothing
here adds package **signature** verification, and moving the hashing into the
module does not make an unsigned package trustworthy — it only means the
integrity check that already existed is performed by the validated module.
