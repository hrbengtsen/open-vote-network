use crate::{OneInTwoZKP, SchnorrProof};
use concordium_std::{trap, Vec};
use group::GroupEncoding;
use k256::elliptic_curve::{PublicKey, ScalarCore, SecretKey};
use k256::{ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

// Check dl zkp: g^w = g^r * g^xz
pub fn verify_dl_zkp(g_x: ProjectivePoint, schnorr: SchnorrProof) -> bool {
    let g_w = convert_vec_to_point(schnorr.g_w);
    let r: Scalar = convert_vec_to_scalar(schnorr.r);
    let value_to_hash = ProjectivePoint::GENERATOR + g_w + g_x;
    let z_hash_value = Sha256::digest(value_to_hash.to_bytes());
    let z: Scalar = From::<&'_ ScalarCore<Secp256k1>>::from(&unwrap_abort(
        ScalarCore::from_be_slice(&z_hash_value).ok(),
    ));
    let g_r = ProjectivePoint::GENERATOR * r;
    let g_x_z = g_x * z;
    let g_rg_x_z: ProjectivePoint = g_x_z + g_r;
    if g_rg_x_z == g_w {
        return true;
    }
    false
}

pub fn verify_one_out_of_two_zkp(zkp: OneInTwoZKP, g_y: ProjectivePoint) -> bool {
    let r1: Scalar = convert_vec_to_scalar(zkp.r1);
    let r2: Scalar = convert_vec_to_scalar(zkp.r2);
    let d1: Scalar = convert_vec_to_scalar(zkp.d1);
    let d2: Scalar = convert_vec_to_scalar(zkp.d2);
    let x = convert_vec_to_point(zkp.x);
    let y = convert_vec_to_point(zkp.y);
    let a1 = convert_vec_to_point(zkp.a1);
    let b1 = convert_vec_to_point(zkp.b1);
    let a2 = convert_vec_to_point(zkp.a2);
    let b2 = convert_vec_to_point(zkp.b2);

    //c = H(i,x,y,a1,b1,a2,b2)
    let value_to_hash = x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    let hash = Sha256::digest(&value_to_hash.to_bytes());
    let c: Scalar = From::<&'_ ScalarCore<Secp256k1>>::from(&unwrap_abort(
        ScalarCore::from_be_slice(&hash).ok(),
    ));

    if c != d1.clone() + d2.clone() {
        return false;
    };
    if a1 != (ProjectivePoint::GENERATOR * r1.clone()) + (x.clone() * d1.clone()) {
        return false;
    }
    if b1 != (g_y.clone() * r1) + (y.clone() * d1) {
        return false;
    }
    if a2 != (ProjectivePoint::GENERATOR * r2.clone()) + (x * d2.clone()) {
        return false;
    }
    if b2 != (g_y * r2) + ((y - ProjectivePoint::GENERATOR) * d2) {
        return false;
    }
    true
}

pub fn check_commitment(vote: ProjectivePoint, commitment: Vec<u8>) -> bool {
    Sha256::digest(&vote.to_bytes().to_vec()).to_vec() == commitment
}

/// yes votes are tallied on chain
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
    //for i in 0.. {
    while current_g != tally {
        yes_votes += 1;
        current_g += &pg;
    }
    yes_votes
}

pub fn convert_vec_to_scalar(vec: Vec<u8>) -> Scalar {
    let scalar_option = SecretKey::<Secp256k1>::from_be_bytes(&vec).ok();

    let scalar = unwrap_abort(scalar_option);

    return From::<&'_ ScalarCore<Secp256k1>>::from(SecretKey::as_scalar_core(&scalar));
}

pub fn convert_vec_to_point(vec: Vec<u8>) -> ProjectivePoint {
    let point_option = PublicKey::<Secp256k1>::from_sec1_bytes(&vec).ok();

    let point = unwrap_abort(point_option);

    return PublicKey::to_projective(&point);
}

#[inline]
pub fn unwrap_abort<T>(o: Option<T>) -> T {
    match o {
        Some(t) => t,
        None => trap(),
    }
}
