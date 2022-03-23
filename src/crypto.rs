use curv::elliptic::curves::{Scalar, Secp256k1};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof};
use sha2::Sha256;

use crate::types;

/// Crypto and ZKP utilities (creation of proofs, etc. should be called locally)

// Check dl zkp: g^w = g^r * g^xz
pub fn verify_dl_zkp(proof: types::DLogProofWrapper) -> bool {
  DLogProof::verify(&proof.0).is_ok()
}

// Create dl zkp (g^w, r = w - xz)
pub fn create_dl_zkp(x: Vec<u8>) -> types::DLogProofWrapper {
  let x_as_scalar = Scalar::from_bytes(&x).unwrap();
  let proof = DLogProof::<Secp256k1, Sha256>::prove(&x_as_scalar);
  
  types::DLogProofWrapper(proof)
}