use group::GroupEncoding;
use k256::elliptic_curve::ff::Field;
use k256::elliptic_curve::{PublicKey, ScalarCore, SecretKey};
use k256::{ProjectivePoint, Scalar, Secp256k1};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

#[derive(Default, PartialEq, Clone)]
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

#[derive(PartialEq, Default, Clone)]
pub struct SchnorrProof {
    r: Vec<u8>,
    g_w: Vec<u8>,
}

// Create a pk, sk pair of g^x and x
pub fn create_votingkey_pair(seed: u64) -> (Scalar, ProjectivePoint) {
    let rng = ChaCha20Rng::seed_from_u64(seed);
    let x = Field::random(rng);
    let g_x = ProjectivePoint::GENERATOR * x;
    (x, g_x)
}

// Create dl zkp (g^w, r = w - xz)
pub fn create_dl_zkp(g_x: ProjectivePoint, x: Scalar) -> SchnorrProof {
    let rng = ChaCha20Rng::seed_from_u64(123);
    let w: Scalar = Scalar::random(rng);
    let g_w = ProjectivePoint::GENERATOR * w;
    let value_to_hash = ProjectivePoint::GENERATOR + g_w + g_x;
    let z_hash_value = Sha256::digest(value_to_hash.to_bytes());
    let z: Scalar = From::<&'_ ScalarCore<Secp256k1>>::from(&
        ScalarCore::from_be_slice(&z_hash_value).unwrap(),
    );
    let r = w - x * z;
    SchnorrProof {
        g_w: g_w.to_bytes().to_vec(),
        r: r.to_bytes().to_vec(),
    }
}

pub fn create_one_out_of_two_zkp_yes(
    g_x: ProjectivePoint,
    g_y: ProjectivePoint,
    x: Scalar,
) -> OneInTwoZKP {
    let rng = ChaCha20Rng::seed_from_u64(123);
    let w = Scalar::random(rng.clone());
    let r1 = Scalar::random(rng.clone());
    let d1 = Scalar::random(rng);
    let y = (g_y.clone() * x.clone()) + ProjectivePoint::GENERATOR;
    let a1 = (ProjectivePoint::GENERATOR * r1.clone()) + (g_x.clone() * d1.clone());
    let b1 = (g_y.clone() * r1.clone()) + (y.clone() * d1.clone());
    let a2 = ProjectivePoint::GENERATOR * w.clone();
    let b2 = g_y * w.clone();

    //c = H(i,x,y,a1,b1,a2,b2)
    let value_to_hash = g_x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    let hash = Sha256::digest(&value_to_hash.to_bytes());
    let c: Scalar = From::<&'_ ScalarCore<Secp256k1>>::from(&
        ScalarCore::from_be_slice(&hash).unwrap(),
    );

    let d2: Scalar = c - d1.clone();
    let r2 = w - (x * d2.clone());

    OneInTwoZKP {
        r1: r1.to_bytes().to_vec(),
        r2: r2.to_bytes().to_vec(),
        d1: d1.to_bytes().to_vec(),
        d2: d2.to_bytes().to_vec(),
        x: g_x.to_bytes().to_vec(),
        y: y.to_bytes().to_vec(),
        a1: a1.to_bytes().to_vec(),
        b1: b1.to_bytes().to_vec(),
        a2: a2.to_bytes().to_vec(),
        b2: b2.to_bytes().to_vec(),
    }
}

pub fn create_one_out_of_two_zkp_no(
    g_x: ProjectivePoint,
    g_y: ProjectivePoint,
    x: Scalar,
) -> OneInTwoZKP {
    let rng = ChaCha20Rng::seed_from_u64(123);
    let w = Scalar::random(rng.clone());
    let r2 = Scalar::random(rng.clone());
    let d2 = Scalar::random(rng.clone());
    let y = g_y.clone() * x.clone();
    let a1 = ProjectivePoint::GENERATOR * w.clone();
    let b1 = g_y.clone() * w.clone();
    let a2 = (ProjectivePoint::GENERATOR * r2.clone()) + (g_x.clone() * d2.clone());
    let b2 = (g_y.clone() * r2.clone()) + ((y.clone() - ProjectivePoint::GENERATOR) * d2.clone());

    //c = H(i,x,y,a1,b1,a2,b2)
    let value_to_hash = g_x.clone() + y.clone() + a1.clone() + b1.clone() + a2.clone() + b2.clone();
    let hash = Sha256::digest(&value_to_hash.to_bytes());
    let c: Scalar = From::<&'_ ScalarCore<Secp256k1>>::from(&
        ScalarCore::from_be_slice(&hash).unwrap(),
    );

    let d1 = c - d2.clone();
    let r1 = w - (x * d1.clone());

    OneInTwoZKP {
        r1: r1.to_bytes().to_vec(),
        r2: r2.to_bytes().to_vec(),
        d1: d1.to_bytes().to_vec(),
        d2: d2.to_bytes().to_vec(),
        x: g_x.to_bytes().to_vec(),
        y: y.to_bytes().to_vec(),
        a1: a1.to_bytes().to_vec(),
        b1: b1.to_bytes().to_vec(),
        a2: a2.to_bytes().to_vec(),
        b2: b2.to_bytes().to_vec(),
    }
}

pub fn compute_reconstructed_key(
    keys: Vec<ProjectivePoint>,
    local_voting_key: ProjectivePoint,
) -> ProjectivePoint {
    //Get our key's position in the list of voting keys
    let position = keys.iter().position(|k| *k == local_voting_key.clone()).unwrap();

    let mut after_points = keys.get(keys.len() - 1).unwrap().clone();
    // Fill after points with every key except the last and return if you are the first
    if position == 0 {
        for i in 1..keys.len() - 1 {
            after_points = after_points + keys.get(i).unwrap().clone();
        }
        return -after_points;
    }

    let mut before_points = keys.get(0).unwrap().clone();
    for j in 1..keys.len() - 1 {
        // Skip your own key
        if j == position {
            continue;
        }

        // add to before points when j is less than your position
        if j < position {
            before_points = before_points + keys.get(j).unwrap().clone();
        }

        // add to after points when j is greater than your position
        if j > position {
            after_points += keys.get(j).unwrap().clone();
        }
    }
    // If you are the last just return before points
    if position == keys.len() - 1 {
        return before_points;
    }
    return before_points - after_points;
}

pub fn commit_to_vote(x: &Scalar, g_y: &ProjectivePoint, g_v: ProjectivePoint) -> Vec<u8> {
    let g_xy_g_v = (g_y * x) + g_v;
    Sha256::digest(&g_xy_g_v.to_bytes().to_vec()).to_vec()
}

pub fn convert_vec_to_scalar(vec: Vec<u8>) -> Scalar {
    let scalar = SecretKey::<Secp256k1>::from_be_bytes(&vec).unwrap();

    return From::<&'_ ScalarCore<Secp256k1>>::from(SecretKey::as_scalar_core(&scalar));
}

pub fn convert_vec_to_point(vec: Vec<u8>) -> ProjectivePoint {
    let point = PublicKey::<Secp256k1>::from_sec1_bytes(&vec).unwrap();

    return PublicKey::to_projective(&point);
}