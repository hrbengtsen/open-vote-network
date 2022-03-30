use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

/// Crypto and ZKP utilities (creation of proofs, etc. should be called locally)

// Create a pk, sk pair of g^x and x
pub fn create_votingkey_pair() -> (Scalar<Secp256k1>, Point<Secp256k1>) {
    let x = Scalar::<Secp256k1>::random();
    let g_x = Point::generator() * x.clone();
    (x, g_x)
}

// Check dl zkp: g^w = g^r * g^xz
pub fn verify_dl_zkp(proof: DLogProof<Secp256k1, Sha256>) -> bool {
    DLogProof::verify(&proof).is_ok()
}

// Create dl zkp (g^w, r = w - xz)
pub fn create_dl_zkp(x: Scalar<Secp256k1>) -> DLogProof<Secp256k1, Sha256> {
    DLogProof::<Secp256k1, Sha256>::prove(&x)
}

pub fn compute_reconstructed_key(
    keys: Vec<Point<Secp256k1>>,
    local_voting_key: Point<Secp256k1>,
) -> Point<Secp256k1> {
    // Get our key's position in the list of voting keys
    let position = keys.iter().position(|k| *k == local_voting_key).unwrap();

    // Case when our key is the first - Probably handled in one case below
    if position == 0 {
        let mut after_points = keys[1].clone();

        for i in 2..keys.len() {
            after_points = after_points + keys[i].clone();
        }
        return after_points;
    }

    // Case when our key is the last
    if position == keys.len() - 1 {
        let mut before_points = keys[0].clone();

        for i in 2..keys.len() {
            before_points = before_points + keys[i].clone();
        }
        return before_points;
    }

    // We are somewhere in the middle
    let mut before_points = keys[0].clone();
    let mut after_points = keys[keys.len() - 1].clone();

    for i in 1..keys.len() - 1 {
        if position == i {
            continue;
        }

        if position > i {
            before_points = before_points + keys[i].clone();
        } else {
            after_points = after_points + keys[i].clone();
        }
    }
    before_points - after_points
}

pub fn commit_to_vote(
    g_x: Point<Secp256k1>,
    g_y: Point<Secp256k1>,
    vote: Scalar<Secp256k1>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();

    let g_xy_g_v = (g_x + g_y) * vote;
    hasher.update(g_xy_g_v.to_bytes(true).to_vec());

    hasher.finalize().to_vec()
}
