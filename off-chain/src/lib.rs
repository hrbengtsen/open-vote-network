//! A Rust crate for the associated off-chain functions to be used
//! along with the *voting* Concordium smart contract.
//!
//! Via this crate voters can create voting key pairs, ZKPs, etc.
//!
//! Ideally, a simple decentralized app would provide an interface to call these functi
use concordium_std::*;
use group::GroupEncoding;
use k256::elliptic_curve::ff::Field;
use k256::{ProjectivePoint, Scalar};
use rand::thread_rng;
use rs_merkle::algorithms::Sha256 as merkle_sha256;
use rs_merkle::*;
use sha2::{Digest, Sha256};
use util::{hash_to_scalar, OneInTwoZKP, SchnorrProof};

/// Create a voting key (pk, sk) pair of g^x and x
pub fn create_votingkey_pair() -> (Scalar, ProjectivePoint) {
    let rng = thread_rng();
    let x = Scalar::random(rng);
    let g_x = ProjectivePoint::GENERATOR * x;
    (x, g_x)
}

/// Create a discrete log Schnorr ZKP (g^w, r = w - xz)
pub fn create_schnorr_zkp(g_x: ProjectivePoint, x: Scalar) -> SchnorrProof {
    let rng = thread_rng();

    let w = Scalar::random(rng);
    let g_w = ProjectivePoint::GENERATOR * w;

    // Create hash z = H(g, g^w, g^x)
    let value_to_hash = ProjectivePoint::GENERATOR + g_w + g_x;
    let z = hash_to_scalar(value_to_hash.to_bytes().to_vec());

    let r = w - x * z;

    SchnorrProof::new(g_w, r)
}

/// Create one-in-two ZKP "yes" instance
pub fn create_one_in_two_zkp_yes(
    g_x: ProjectivePoint,
    g_y: ProjectivePoint,
    x: Scalar,
) -> OneInTwoZKP {
    let rng = thread_rng();

    // Create random scalars in prime field for "yes"
    let w = Scalar::random(rng.clone());
    let r1 = Scalar::random(rng.clone());
    let d1 = Scalar::random(rng);

    // Create the rest of the neccessary variables for the proof
    let y = (g_y.clone() * x.clone()) + ProjectivePoint::GENERATOR;
    let a1 = (ProjectivePoint::GENERATOR * r1.clone()) + (g_x.clone() * d1.clone());
    let b1 = (g_y.clone() * r1.clone()) + (y.clone() * d1.clone());
    let a2 = ProjectivePoint::GENERATOR * w.clone();
    let b2 = g_y * w.clone();

    // c = H(g^x, y, a1, b1, a2, b2)
    let value_to_hash = g_x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    let c = hash_to_scalar(value_to_hash.to_bytes().to_vec());

    let d2: Scalar = c - d1.clone();
    let r2 = w - (x * d2.clone());

    OneInTwoZKP::new(r1, r2, d1, d2, g_x, y, a1, b1, a2, b2)
}

/// Create one-in-two ZKP "no" instance
pub fn create_one_in_two_zkp_no(
    g_x: ProjectivePoint,
    g_y: ProjectivePoint,
    x: Scalar,
) -> OneInTwoZKP {
    let rng = thread_rng();

    // Create random scalars in prime field for "no"
    let w = Scalar::random(rng.clone());
    let r2 = Scalar::random(rng.clone());
    let d2 = Scalar::random(rng.clone());

    // Create the rest of the neccessary variables for the proof
    let y = g_y.clone() * x.clone();
    let a1 = ProjectivePoint::GENERATOR * w.clone();
    let b1 = g_y.clone() * w.clone();
    let a2 = (ProjectivePoint::GENERATOR * r2.clone()) + (g_x.clone() * d2.clone());
    let b2 = (g_y.clone() * r2.clone()) + ((y.clone() - ProjectivePoint::GENERATOR) * d2.clone());

    // c = H(g^x, y, a1, b1, a2, b2)
    let value_to_hash = g_x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    let c = hash_to_scalar(value_to_hash.to_bytes().to_vec());

    let d1 = c - d2.clone();
    let r1 = w - (x * d1.clone());

    OneInTwoZKP::new(r1, r2, d1, d2, g_x, y, a1, b1, a2, b2)
}

/// Compute a voter's reconstructed key (g^y) from their voting key (g^x) and all other voting keys in a given vote
/// Note: It's important that the list of keys is in the same order for all voters
pub fn compute_reconstructed_key(
    keys: &Vec<ProjectivePoint>,
    g_x: ProjectivePoint,
) -> ProjectivePoint {
    //Get our key's position in the list of voting keys
    let position = keys.iter().position(|k| *k == g_x.clone()).unwrap();

    let mut after_points = keys[keys.len() - 1].clone();
    // Fill after points with every key except the last and return if you are the first
    if position == 0 {
        for i in 1..keys.len() - 1 {
            after_points = after_points + keys[i].clone();
        }
        return -after_points;
    }

    let mut before_points = keys[0].clone();
    for j in 1..keys.len() - 1 {
        // Skip your own key
        if j == position {
            continue;
        }

        // add to before points when j is less than your position
        if j < position {
            before_points = before_points + keys[j].clone();
        }

        // add to after points when j is greater than your position
        if j > position {
            after_points += keys[j].clone();
        }
    }
    // If you are the last just return before points
    if position == keys.len() - 1 {
        return before_points;
    }
    return before_points - after_points;
}

/// Create a commitment to a vote: H(g^xy g^v)
pub fn commit_to_vote(x: &Scalar, g_y: &ProjectivePoint, g_v: ProjectivePoint) -> Vec<u8> {
    let g_xy_g_v = (g_y * x) + g_v;
    Sha256::digest(&g_xy_g_v.to_bytes().to_vec()).to_vec()
}

/// Create a merkle tree for storing its root in the contract via the voteconfig
pub fn create_merkle_tree(leaf_values: &Vec<AccountAddress>) -> MerkleTree<merkle_sha256> {
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    leaves.extend(
        leaf_values
            .iter()
            .map(|x| merkle_sha256::hash(&to_bytes(x))),
    );

    let merkle_tree = MerkleTree::<merkle_sha256>::from_leaves(&leaves);

    merkle_tree
}

/// Create a merkle proof-of-membership via your AccountAddress and the tree itself
pub fn create_merkle_proof(
    account: AccountAddress,
    merkle_tree: &MerkleTree<merkle_sha256>,
) -> util::MerkleProof {
    let leaves = merkle_tree.leaves().unwrap();
    let index_to_prove = leaves
        .iter()
        .position(|&l| l == merkle_sha256::hash(&to_bytes(&account)))
        .ok_or("Can't get index to prove. AccountAddress not in MerkleTree")
        .unwrap();

    let leaf_to_prove = leaves
        .get(index_to_prove)
        .ok_or("Can't get leaf to prove")
        .unwrap();
    let merkle_proof = merkle_tree.proof(&[index_to_prove]);

    util::MerkleProof {
        proof: merkle_proof.to_bytes(),
        leaf: *leaf_to_prove,
        index: index_to_prove as i32,
    }
}
