//! A Rust crate containing common types and utility functions used internally in the other crates.

use concordium_std::*;
use group::GroupEncoding;
use k256::elliptic_curve::{PublicKey, ScalarCore, SecretKey};
use k256::{ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

#[derive(Serialize, SchemaType, Default, PartialEq, Clone)]
pub struct OneInTwoZKP {
    r1: Vec<u8>,
    r2: Vec<u8>,
    d1: Vec<u8>,
    d2: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
    a1: Vec<u8>,
    b1: Vec<u8>,
    a2: Vec<u8>,
    b2: Vec<u8>,
}

impl OneInTwoZKP {
    /// Create a new OneInTwoZKP
    pub fn new(
        r1: Scalar,
        r2: Scalar,
        d1: Scalar,
        d2: Scalar,
        x: ProjectivePoint,
        y: ProjectivePoint,
        a1: ProjectivePoint,
        b1: ProjectivePoint,
        a2: ProjectivePoint,
        b2: ProjectivePoint,
    ) -> Self {
        Self {
            r1: r1.to_bytes().to_vec(),
            r2: r2.to_bytes().to_vec(),
            d1: d1.to_bytes().to_vec(),
            d2: d2.to_bytes().to_vec(),
            x: x.to_bytes().to_vec(),
            y: y.to_bytes().to_vec(),
            a1: a1.to_bytes().to_vec(),
            b1: b1.to_bytes().to_vec(),
            a2: a2.to_bytes().to_vec(),
            b2: b2.to_bytes().to_vec(),
        }
    }

    /// Extract the Scalars of the proof: (r1, r2, d1, d2)
    pub fn extract_scalars(&self) -> (Scalar, Scalar, Scalar, Scalar) {
        (
            convert_vec_to_scalar(&self.r1),
            convert_vec_to_scalar(&self.r2),
            convert_vec_to_scalar(&self.d1),
            convert_vec_to_scalar(&self.d2),
        )
    }

    /// Extract the Points of the proof: (x, y, a1, b1, a2, b2)
    pub fn extract_points(
        &self,
    ) -> (
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
    ) {
        (
            convert_vec_to_point(&self.x),
            convert_vec_to_point(&self.y),
            convert_vec_to_point(&self.a1),
            convert_vec_to_point(&self.b1),
            convert_vec_to_point(&self.a2),
            convert_vec_to_point(&self.b2),
        )
    }
}

#[derive(Serialize, SchemaType, PartialEq, Default, Clone)]
pub struct SchnorrProof {
    pub g_w: Vec<u8>,
    pub r: Vec<u8>,
}

impl SchnorrProof {
    /// Create a new SchnorrProof
    pub fn new(g_w: ProjectivePoint, r: Scalar) -> Self {
        Self {
            g_w: g_w.to_bytes().to_vec(),
            r: r.to_bytes().to_vec(),
        }
    }

    /// Extract the primitives of the proof: (g_w, r)
    pub fn extract_primitives(&self) -> (ProjectivePoint, Scalar) {
        (
            convert_vec_to_point(&self.g_w),
            convert_vec_to_scalar(&self.r),
        )
    }
}

#[derive(Serialize, SchemaType, PartialEq)]
pub struct MerkleProof {
    pub proof: Vec<u8>,
    pub leaf: [u8; 32],
    pub index: i32,
}

/// Utility function to convert Vec -> Scalar
pub fn convert_vec_to_scalar(vec: &Vec<u8>) -> Scalar {
    let scalar_option = SecretKey::<Secp256k1>::from_be_bytes(vec).ok();

    let scalar = unwrap_abort(scalar_option);

    return From::<&'_ ScalarCore<Secp256k1>>::from(SecretKey::as_scalar_core(&scalar));
}

/// Utility function to convert Vec -> ProjectivePoint
pub fn convert_vec_to_point(vec: &Vec<u8>) -> ProjectivePoint {
    let point_option = PublicKey::<Secp256k1>::from_sec1_bytes(vec).ok();

    let point = unwrap_abort(point_option);

    return PublicKey::to_projective(&point);
}

/// Utility function to go from Vec -> Hash -> Scalar
pub fn hash_to_scalar(bytes_to_hash: Vec<u8>) -> Scalar {
    let hash_value = Sha256::digest(bytes_to_hash);

    return convert_vec_to_scalar(&hash_value.to_vec());
}

/// Utility to better unwrap a value in WASM
#[inline]
pub fn unwrap_abort<T>(o: Option<T>) -> T {
    match o {
        Some(t) => t,
        None => trap(),
    }
}
