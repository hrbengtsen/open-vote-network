use curv::elliptic::curves::{Scalar, Secp256k1};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof};
use sha2::Sha256;

/// Crypto and ZKP utilities (creation of proofs, etc. should be called locally)

// Check dl zkp: g^w = g^r * g^xz
pub fn verify_dl_zkp(proof: DLogProof<Secp256k1, Sha256>) -> bool {
  DLogProof::verify(&proof).is_ok()
}

// Create dl zkp (g^w, r = w - xz)
pub fn create_dl_zkp(x: Scalar<Secp256k1>) -> DLogProof<Secp256k1, Sha256> {
  DLogProof::<Secp256k1, Sha256>::prove(&x)
}