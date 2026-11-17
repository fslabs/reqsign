// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Hash related utils.

use crate::Error;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;

/// Hashes from AWS-LC, selected by the `aws-lc-rs` or `aws-lc-rs-fips` feature.
#[cfg(any(feature = "aws-lc-rs", feature = "aws-lc-rs-fips"))]
mod backend {
    use aws_lc_rs::digest;
    use aws_lc_rs::hmac;

    pub(super) fn sha1(content: &[u8]) -> impl AsRef<[u8]> {
        digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, content)
    }

    pub(super) fn sha256(content: &[u8]) -> impl AsRef<[u8]> {
        digest::digest(&digest::SHA256, content)
    }

    pub(super) fn hmac_sha1(key: &[u8], content: &[u8]) -> impl AsRef<[u8]> {
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key),
            content,
        )
    }

    pub(super) fn hmac_sha256(key: &[u8], content: &[u8]) -> impl AsRef<[u8]> {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), content)
    }
}

/// Hashes from RustCrypto, the default.
#[cfg(not(any(feature = "aws-lc-rs", feature = "aws-lc-rs-fips")))]
mod backend {
    use hmac::Hmac;
    use hmac::KeyInit;
    use hmac::Mac;
    use sha1::Sha1;
    use sha2::Digest;
    use sha2::Sha256;

    pub(super) fn sha1(content: &[u8]) -> impl AsRef<[u8]> {
        Sha1::digest(content)
    }

    pub(super) fn sha256(content: &[u8]) -> impl AsRef<[u8]> {
        Sha256::digest(content)
    }

    pub(super) fn hmac_sha1(key: &[u8], content: &[u8]) -> impl AsRef<[u8]> {
        // SAFETY: HMAC's new_from_slice always returns Ok - it handles any key length
        let mut h = Hmac::<Sha1>::new_from_slice(key).unwrap();
        h.update(content);
        h.finalize().into_bytes()
    }

    pub(super) fn hmac_sha256(key: &[u8], content: &[u8]) -> impl AsRef<[u8]> {
        // SAFETY: HMAC's new_from_slice always returns Ok - it handles any key length
        let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
        h.update(content);
        h.finalize().into_bytes()
    }
}

/// Base64 encode
pub fn base64_encode(content: &[u8]) -> String {
    BASE64_STANDARD.encode(content)
}

/// Base64 decode
pub fn base64_decode(content: &str) -> crate::Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(content)
        .map_err(|e| Error::unexpected("base64 decode failed").with_source(e))
}

/// Hex encoded SHA1 hash.
///
/// Use this function instead of `hex::encode(sha1(content))` can reduce
/// extra copy.
pub fn hex_sha1(content: &[u8]) -> String {
    hex::encode(backend::sha1(content))
}

/// Hex encoded SHA256 hash.
///
/// Use this function instead of `hex::encode(sha256(content))` can reduce
/// extra copy.
pub fn hex_sha256(content: &[u8]) -> String {
    hex::encode(backend::sha256(content))
}

/// HMAC with SHA256 hash.
pub fn hmac_sha256(key: &[u8], content: &[u8]) -> Vec<u8> {
    backend::hmac_sha256(key, content).as_ref().to_vec()
}

/// Base64 encoded HMAC with SHA256 hash.
pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    base64_encode(backend::hmac_sha256(key, content).as_ref())
}

/// Hex encoded HMAC with SHA1 hash.
///
/// Use this function instead of `hex::encode(hmac_sha1(key, content))` can
/// reduce extra copy.
pub fn hex_hmac_sha1(key: &[u8], content: &[u8]) -> String {
    hex::encode(backend::hmac_sha1(key, content))
}

/// Hex encoded HMAC with SHA256 hash.
///
/// Use this function instead of `hex::encode(hmac_sha256(key, content))` can
/// reduce extra copy.
pub fn hex_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    hex::encode(backend::hmac_sha256(key, content))
}

/// Base64 encoded HMAC with SHA1 hash.
pub fn base64_hmac_sha1(key: &[u8], content: &[u8]) -> String {
    base64_encode(backend::hmac_sha1(key, content).as_ref())
}
