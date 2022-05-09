//! Rust file containing the required on-chain crypto functions needed in the *voting* contract.
//! 
//! These are verifications of ZKPs, checking vote commitments and brute forcing the final tally.

use concordium_std::{Vec};
use group::GroupEncoding;
use k256::{ProjectivePoint};
use sha2::{Digest, Sha256};
use util::{OneInTwoZKP, SchnorrProof, hash_to_scalar, unwrap_abort};

/// Check Schnorr ZKP: g^w = g^r * g^xz
pub fn verify_schnorr_zkp(g_x: ProjectivePoint, schnorr: util::SchnorrProof) -> bool {
    let (g_w, r) = SchnorrProof::extract_primitives(&schnorr);

    // Create hash z = H(g, g^w, g^x)
    let value_to_hash = ProjectivePoint::GENERATOR + g_w + g_x;
    let z = hash_to_scalar(value_to_hash.to_bytes().to_vec());

    let g_r = ProjectivePoint::GENERATOR * r;
    let g_x_z = g_x * z;
    let g_rg_x_z: ProjectivePoint = g_x_z + g_r;

    if g_rg_x_z == g_w {
        return true;
    }
    false
}

/// Check one-in-two ZKP: check v = 1 or v = 0 without knowing which
pub fn verify_one_in_two_zkp(zkp: util::OneInTwoZKP, g_y: ProjectivePoint) -> bool {
    let (r1, r2, d1, d2) = OneInTwoZKP::extract_scalars(&zkp);

    let (x, y, a1, b1, a2, b2) = OneInTwoZKP::extract_points(&zkp);

    // c = H(g^x, y, a1, b1, a2, b2)
    let value_to_hash = x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    let c = hash_to_scalar(value_to_hash.to_bytes().to_vec());

    if c != d1.clone() + d2.clone() {
        println!("c is fucked");
        return false;
    };
    if a1 != (ProjectivePoint::GENERATOR * r1.clone()) + (x.clone() * d1.clone()) {
        println!("a1 is fucked");
        return false;
    }
    if b1 != (g_y.clone() * r1) + (y.clone() * d1) {
        println!("b1 is fucked");
        return false;
    }
    if a2 != (ProjectivePoint::GENERATOR * r2.clone()) + (x * d2.clone()) {
        println!("a2 is fucked");
        return false;
    }
    if b2 != (g_y * r2) + ((y - ProjectivePoint::GENERATOR) * d2) {
        println!("b2 is fucked");
        return false;
    }
    true
}

/// Check commitment matches actual vote
pub fn check_commitment(vote: ProjectivePoint, commitment: Vec<u8>) -> bool {
    Sha256::digest(&vote.to_bytes().to_vec()).to_vec() == commitment
}

/// Brute force and tally yes votes on-chain
pub fn brute_force_tally(votes: Vec<ProjectivePoint>) -> i32 {
    // Set first vote as initial tally
    let mut tally = unwrap_abort(votes.get(0)).clone();

    for i in 1..votes.len() {
        // Add all the rest of the votes (curve points) to tally, e.g \prod g^xy*g^v (calculated differently due to additive curve)
        tally = tally + unwrap_abort(votes.get(i));
    }

    let mut current_g = ProjectivePoint::IDENTITY;
    let mut yes_votes = 0;
    let pg = ProjectivePoint::GENERATOR;

    // Go through all votes and brute force number of yes votes
    while current_g != tally {
        yes_votes += 1;
        current_g += &pg;
    }
    yes_votes
}
