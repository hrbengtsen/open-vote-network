pub mod lib;
use concordium_std::*;
use group::GroupEncoding;
use k256::{ProjectivePoint, Scalar};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, Write};
use std::path::Path;
use util::{hash_to_scalar, OneInTwoZKP, SchnorrProof};
use voting::*;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    let (list_of_scalar, list_of_voting_keys) = make_register_msg(args[1].parse().unwrap())?;
    let list_of_reconstructed_keys =
        make_commit_msg(list_of_scalar.clone(), list_of_voting_keys.clone())?;
    make_vote_msg(
        list_of_scalar,
        list_of_voting_keys,
        list_of_reconstructed_keys,
    )?;

    Ok(())
}

pub fn make_register_msg(
    number_of_voters: i32,
) -> std::io::Result<(Vec<Scalar>, Vec<ProjectivePoint>)> {
    let mut list_of_scalar: Vec<Scalar> = Vec::new();
    let mut list_of_voting_keys: Vec<ProjectivePoint> = Vec::new();
    for i in 0..number_of_voters {
        let (x, g_x) = lib::create_votingkey_pair();
        let schnorr = lib::create_schnorr_zkp(g_x, x);

        let file_name = format!("../voting/parameters/register_msgs/register_msg{}.bin", i);
        let mut file = File::create(file_name)?;

        let register_msg = RegisterMessage {
            voting_key: g_x.to_bytes().to_vec(),
            voting_key_zkp: schnorr,
        };

        list_of_scalar.push(x);
        list_of_voting_keys.push(g_x);

        file.write_all(&to_bytes(&register_msg))?;
    }
    Ok((list_of_scalar, list_of_voting_keys))
}

pub fn make_commit_msg(
    list_of_scalar: Vec<Scalar>,
    list_of_voting_keys: Vec<ProjectivePoint>,
) -> std::io::Result<Vec<ProjectivePoint>> {
    let mut list_of_reconstructed_keys: Vec<ProjectivePoint> = Vec::new();

    for i in 0..list_of_voting_keys.clone().len() {
        let g_y =
            off_chain::compute_reconstructed_key(&list_of_voting_keys, list_of_voting_keys[i]);
        let g_v = ProjectivePoint::GENERATOR;
        let commitment = off_chain::commit_to_vote(&list_of_scalar[i], &g_y, g_v);

        let commit_msg = CommitMessage {
            reconstructed_key: g_y.to_bytes().to_vec(),
            commitment,
        };

        list_of_reconstructed_keys.push(g_y);

        let file_name = format!("../voting/parameters/commit_msgs/commit_msg{}.bin", i);
        let mut file = File::create(file_name)?;

        file.write_all(&to_bytes(&commit_msg))?;
    }

    Ok(list_of_reconstructed_keys)
}

pub fn make_vote_msg(
    list_of_scalar: Vec<Scalar>,
    list_of_voting_keys: Vec<ProjectivePoint>,
    list_of_reconstructed_keys: Vec<ProjectivePoint>,
) -> std::io::Result<()> {
    for i in 0..list_of_voting_keys.clone().len() {
        let vote = (list_of_reconstructed_keys[i] * list_of_scalar[i]) + ProjectivePoint::GENERATOR;
        let vote_zkp = off_chain::create_one_in_two_zkp_yes(
            list_of_voting_keys[i],
            list_of_reconstructed_keys[i],
            list_of_scalar[i],
        );

        let vote_msg = VoteMessage {
            vote: vote.to_bytes().to_vec(),
            vote_zkp,
        };

        let file_name = format!("../voting/parameters/vote_msgs/vote_msg{}.bin", i);
        let mut file = File::create(file_name)?;

        file.write_all(&to_bytes(&vote_msg))?;
    }

    Ok(())
}
