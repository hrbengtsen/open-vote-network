use crate::OneInTwoZKP;
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

pub fn create_one_out_of_two_zkp_yes(
    g_x: Point<Secp256k1>,
    g_y: Point<Secp256k1>,
    x: Scalar<Secp256k1>,
) -> OneInTwoZKP {
    let w = Scalar::<Secp256k1>::random();
    let r1 = Scalar::<Secp256k1>::random();
    let d1 = Scalar::<Secp256k1>::random();
    let y = (g_y.clone() * x.clone()) + Point::generator();
    let a1 = (Point::generator() * r1.clone()) + (g_x.clone() * d1.clone());
    let b1 = (g_y.clone() * r1.clone()) + (y.clone() * d1.clone());
    let a2 = Point::generator() * w.clone();
    let b2 = g_y * w.clone();

    //c = H(i,x,y,a1,b1,a2,b2)
    let mut hasher = Sha256::new();
    let value_to_hash = g_x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    hasher.update(value_to_hash.to_bytes(true).to_vec());
    let c = Scalar::<Secp256k1>::from_bytes(&hasher.finalize().to_vec()).unwrap();

    let d2 = c - d1.clone();
    let r2 = w - (x * d2.clone());

    OneInTwoZKP {
        r1: r1.to_bytes().to_vec(),
        r2: r2.to_bytes().to_vec(),
        d1: d1.to_bytes().to_vec(),
        d2: d2.to_bytes().to_vec(),
        x: g_x.to_bytes(true).to_vec(),
        y: y.to_bytes(true).to_vec(),
        a1: a1.to_bytes(true).to_vec(),
        b1: b1.to_bytes(true).to_vec(),
        a2: a2.to_bytes(true).to_vec(),
        b2: b2.to_bytes(true).to_vec(),
    }
}

pub fn create_one_out_of_two_zkp_no(
    g_x: Point<Secp256k1>,
    g_y: Point<Secp256k1>,
    x: Scalar<Secp256k1>,
) -> OneInTwoZKP {
    let w = Scalar::<Secp256k1>::random();
    let r2 = Scalar::<Secp256k1>::random();
    let d2 = Scalar::<Secp256k1>::random();
    let y = g_y.clone() * x.clone();
    let a1 = Point::generator() * w.clone();
    let b1 = g_y.clone() * w.clone();
    let a2 = (Point::generator() * r2.clone()) + (g_x.clone() * d2.clone());
    let b2 = (g_y.clone() * r2.clone()) + ((y.clone() - Point::generator()) * d2.clone());

    //c = H(i,x,y,a1,b1,a2,b2)
    let mut hasher = Sha256::new();
    let value_to_hash = g_x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    hasher.update(value_to_hash.to_bytes(true).to_vec());
    let c = Scalar::<Secp256k1>::from_bytes(&hasher.finalize().to_vec()).unwrap();

    let d1 = c - d2.clone();
    let r1 = w - (x * d1.clone());

    OneInTwoZKP {
        r1: r1.to_bytes().to_vec(),
        r2: r2.to_bytes().to_vec(),
        d1: d1.to_bytes().to_vec(),
        d2: d2.to_bytes().to_vec(),
        x: g_x.to_bytes(true).to_vec(),
        y: y.to_bytes(true).to_vec(),
        a1: a1.to_bytes(true).to_vec(),
        b1: b1.to_bytes(true).to_vec(),
        a2: a2.to_bytes(true).to_vec(),
        b2: b2.to_bytes(true).to_vec(),
    }
}

pub fn verify_one_out_of_two_zkp(zkp: OneInTwoZKP, g_y: Point<Secp256k1>) -> bool {
    let r1 = Scalar::<Secp256k1>::from_bytes(&zkp.r1).unwrap();
    let r2 = Scalar::<Secp256k1>::from_bytes(&zkp.r2).unwrap();
    let d1 = Scalar::<Secp256k1>::from_bytes(&zkp.d1).unwrap();
    let d2 = Scalar::<Secp256k1>::from_bytes(&zkp.d2).unwrap();
    let x = Point::<Secp256k1>::from_bytes(&zkp.x).unwrap();
    let y = Point::<Secp256k1>::from_bytes(&zkp.y).unwrap();
    let a1 = Point::<Secp256k1>::from_bytes(&zkp.a1).unwrap();
    let b1 = Point::<Secp256k1>::from_bytes(&zkp.b1).unwrap();
    let a2 = Point::<Secp256k1>::from_bytes(&zkp.a2).unwrap();
    let b2 = Point::<Secp256k1>::from_bytes(&zkp.b2).unwrap();

    //c = H(i,x,y,a1,b1,a2,b2)
    let mut hasher = Sha256::new();
    let value_to_hash = x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    hasher.update(value_to_hash.to_bytes(true).to_vec());
    let c = Scalar::<Secp256k1>::from_bytes(&hasher.finalize().to_vec()).unwrap();

    if c != d1.clone() + d2.clone() {
        return false;
    };
    if a1 != (Point::generator() * r1.clone()) + (x.clone() * d1.clone()) {
        return false;
    }
    if b1 != (g_y.clone() * r1) + (y.clone() * d1) {
        return false;
    }
    if a2 != (Point::generator() * r2.clone()) + (x * d2.clone()) {
        return false;
    }
    if b2 != (g_y * r2) + ((y - Point::generator()) * d2) {
        return false;
    }
    true
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
    x: Scalar<Secp256k1>,
    g_y: Point<Secp256k1>,
    g_v: Point<Secp256k1>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();

    let g_xy_g_v = (g_y * x) + g_v;
    hasher.update(g_xy_g_v.to_bytes(true).to_vec());

    hasher.finalize().to_vec()
}

/// yes votes are tallied on chain
pub fn brute_force_tally(votes: Vec<Point<Secp256k1>>) -> i32 {
    let mut tally = votes[0].clone();
    for i in 1..votes.len() {
        tally = tally + &votes[i];
    }

    let mut current_g = Point::generator().to_point();
    let mut yes_votes = 0;
    while current_g != tally {
        yes_votes = yes_votes + 1;
        current_g = current_g + Point::generator();
    }
    yes_votes
}
