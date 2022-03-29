use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
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

pub fn compute_reconstructed_key(keys: Vec<Vec<u8>>, local_voting_key: Vec<u8>) -> Vec<u8> {
    // Get our key's position in the list of voting keys
    let position = keys.iter().position(|k| *k == local_voting_key).unwrap();

    // Case when our key is the first - Probably handled in one case below
    if position == 0 {
        let mut after_points = Point::<Secp256k1>::from_bytes(&keys[1]).unwrap();

        for i in 2..keys.len() {
            after_points = after_points + Point::<Secp256k1>::from_bytes(&keys[i]).unwrap();
        }
        return after_points.to_bytes(true).to_vec();
    }

    // Case when our key is the last
    if position == keys.len() - 1 {
        let mut before_points = Point::<Secp256k1>::from_bytes(&keys[0]).unwrap();

        for i in 2..keys.len() {
            before_points = before_points + Point::<Secp256k1>::from_bytes(&keys[i]).unwrap();
        }
        return before_points.to_bytes(true).to_vec();
    }

    // We are somewhere in the middle
    let mut before_points = Point::<Secp256k1>::from_bytes(&keys[0]).unwrap();
    let mut after_points = Point::<Secp256k1>::from_bytes(&keys[keys.len() - 1]).unwrap();

    for i in 1..keys.len() - 1 {
        if position == i {
            continue;
        }

        if position > i {
            before_points = before_points + Point::<Secp256k1>::from_bytes(&keys[i]).unwrap();
        } else {
            after_points = after_points + Point::<Secp256k1>::from_bytes(&keys[i]).unwrap();
        }
    }
    (before_points - after_points).to_bytes(true).to_vec()
}
