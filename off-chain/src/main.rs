//! Rust binary entry point for locally creating binary files of voter messages, for the purpose of testing a full election on-chain.
//!
//! In order to make an actual vote, and not just run this test, this program needs to be modified in 2 ways:
//!
//! 1. Needs to take an argument for the vote.
//! 2. Every voter needs a way to get eachothers reconstructed keys (g_y).
//!    This could be done by modifying the program such that it only creates one message at a time (through some argument)
//!    and adding a getter (view function) to the smart contract to retrieve reconstructed keys.
//!
//! Ideally, a simple decentralized app would provide an interface to the above, such that voter's wouldn't need to download and run this code and call the contract directly themselves.

use concordium_std::*;
use group::GroupEncoding;
use k256::{ProjectivePoint, Scalar};
use std::env;
use std::fs;
use std::fs::File;
use std::io::{Error, Write};
use voting::*;

pub mod lib;

/// Entry point taking an argument of the number of voter's to create messages for (cargo run [number_of_voters])
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

/// Generates (x, g_x) and uses them to create register messages as binaries
pub fn make_register_msg(
    number_of_voters: i32,
) -> std::io::Result<(Vec<Scalar>, Vec<ProjectivePoint>)> {
    let mut list_of_scalar: Vec<Scalar> = Vec::new();
    let mut list_of_voting_keys: Vec<ProjectivePoint> = Vec::new();

    for i in 0..number_of_voters {
        let (x, g_x) = lib::create_votingkey_pair();
        let schnorr = lib::create_schnorr_zkp(g_x, x);

        fs::create_dir_all("../voting/parameters/register_msgs")?;

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

// Generates reconstructed keys and vote commitments to create commit messages as binaries
pub fn make_commit_msg(
    list_of_scalar: Vec<Scalar>,
    list_of_voting_keys: Vec<ProjectivePoint>,
) -> std::io::Result<Vec<ProjectivePoint>> {
    let mut list_of_reconstructed_keys: Vec<ProjectivePoint> = Vec::new();

    for i in 0..list_of_voting_keys.clone().len() {
        let g_y =
            off_chain::compute_reconstructed_key(&list_of_voting_keys, list_of_voting_keys[i]);

        // Currently hardcoded such that all voters will commit to voting "yes"
        let g_v = ProjectivePoint::GENERATOR;

        let commitment = off_chain::commit_to_vote(&list_of_scalar[i], &g_y, g_v);

        let commit_msg = CommitMessage {
            reconstructed_key: g_y.to_bytes().to_vec(),
            commitment,
        };

        list_of_reconstructed_keys.push(g_y);

        fs::create_dir_all("../voting/parameters/commit_msgs")?;

        let file_name = format!("../voting/parameters/commit_msgs/commit_msg{}.bin", i);
        let mut file = File::create(file_name)?;

        file.write_all(&to_bytes(&commit_msg))?;
    }

    Ok(list_of_reconstructed_keys)
}

// Generates vote and its one-in-two ZKP to create vote messages as binaries
pub fn make_vote_msg(
    list_of_scalar: Vec<Scalar>,
    list_of_voting_keys: Vec<ProjectivePoint>,
    list_of_reconstructed_keys: Vec<ProjectivePoint>,
) -> std::io::Result<()> {
    for i in 0..list_of_voting_keys.clone().len() {
        // Hardcoded such that all voters vote "yes"
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

        fs::create_dir_all("../voting/parameters/vote_msgs")?;

        let file_name = format!("../voting/parameters/vote_msgs/vote_msg{}.bin", i);
        let mut file = File::create(file_name)?;

        file.write_all(&to_bytes(&vote_msg))?;
    }

    Ok(())
}
