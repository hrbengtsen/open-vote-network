//! Rust binary entry point for locally creating binary files of voter messages, for the purpose of testing a full election on-chain.
//!
//! In order to make an actual vote, and not just run this test, this program needs to be modified in 3 ways:
//!
//! 1. Needs to take an argument for the vote.
//! 2. Every voter needs a way to get eachothers reconstructed keys (g_y).
//!    This could be done by modifying the program such that it only creates one message at a time (through some argument)
//!    and adding a getter (view function) to the smart contract to retrieve reconstructed keys.
//! 3. A way of publishing the merkle tree to all voters.
//!
//! Ideally, a simple decentralized app would provide an interface to the above, such that voter's wouldn't need to download and run this code and call the contract directly themselves.

use base58check::*;
use concordium_std::*;
use group::GroupEncoding;
use k256::{ProjectivePoint, Scalar};
use rs_merkle::algorithms::Sha256 as merkle_sha256;
use rs_merkle::*;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::io::{Error, Write};
use std::str::FromStr;
use voting::*;

pub mod lib;

/// Entry point taking an argument of the number of voter's to create messages for (cargo run)
fn main() -> Result<(), Error> {
    let (merkle_tree, voter_accounts) = make_voteconfig_json()?;

    let (list_of_scalar, list_of_voting_keys) =
        make_register_msg(merkle_tree, voter_accounts)?;

    let list_of_reconstructed_keys =
        make_commit_msg(list_of_scalar.clone(), list_of_voting_keys.clone())?;

    make_vote_msg(
        list_of_scalar,
        list_of_voting_keys,
        list_of_reconstructed_keys,
    )?;

    Ok(())
}

pub struct AccountAddress2(AccountAddress);

impl FromStr for AccountAddress2 {
    type Err = ();

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let (version, body) = v.from_base58check().map_err(|_| ())?;
        if version == 1 && body.len() == ACCOUNT_ADDRESS_SIZE {
            let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE];
            buf.copy_from_slice(&body);
            Ok(AccountAddress2(AccountAddress(buf)))
        } else {
            Err(())
        }
    }
}

/// Generates voteconfig and creates MerkleTree
pub fn make_voteconfig_json() -> std::io::Result<(MerkleTree<merkle_sha256>, Vec<AccountAddress>)> {
    let voter_accounts = vec![
        AccountAddress2::from_str("4SxRVot39zszDDGe1jqprRHbF3D13EJ4MA7i2BMK88kfqG74TB")
            .unwrap()
            .0,
        AccountAddress2::from_str("3n1ogkGKpdXavtV5AKLeEMbyveZs9NXiVcWcjVeTBVzav6CmZK")
            .unwrap()
            .0,
        AccountAddress2::from_str("4mFJcz47gStZE1PqcKisYQsHRYSYTSByPYBaQWK818z71ympj7")
            .unwrap()
            .0,
        AccountAddress2::from_str("3xZ3bWixa3d9WUtWR1d7imnNgvRJnzWJUCcy4mQMJXo8UQvt8C")
            .unwrap()
            .0,
        AccountAddress2::from_str("35RAEq3DsLwkd92b3esHxxBh8JyTpvJPcnKQ7ZoJZ3Yg3qLBqC")
            .unwrap()
            .0,
        AccountAddress2::from_str("3FibLDUUXmoawtbu4CxHrQ1xo3tu2NwhCeu1xTfhYxgM63V71n")
            .unwrap()
            .0,
        AccountAddress2::from_str("3vtnN9YhLwBdvnHRkF1Y4xkbZKEnnEroAaWmWuWRQ3c8uss1Xd")
            .unwrap()
            .0,
        AccountAddress2::from_str("3PQnFEdEQ4F9TSSD5XggYr8MKZcUEfsZ6w4m8CjwkkxBkLZoAY")
            .unwrap()
            .0,
        AccountAddress2::from_str("36gPYmMbHdvzuWmWzciacw6iUS8jg8gFXkgkCeYGFipEzeoHW5")
            .unwrap()
            .0,
        AccountAddress2::from_str("3XwjPSYEbRKjj1dGDVkH19ixtTJHTJw8p9PV19ABtio3vXN31D")
            .unwrap()
            .0,
        AccountAddress2::from_str("49GEKXLHAq2cJqDnemFTVXP1nov8UGkpNJJyXdKQMsAd9JDmxr")
            .unwrap()
            .0,
        AccountAddress2::from_str("43EHTjg4x2gU3EpiJLCqL9kU78wyxwME7CohWVr5pdzjgpgRdd")
            .unwrap()
            .0,
        AccountAddress2::from_str("45zbAdUr8kc5ZNHhkMVQo9fkAgvVV8mtLqrUeFGBUtz81tx28W")
            .unwrap()
            .0,
        AccountAddress2::from_str("3nP31297qxnQK61eYKaAogkhhRNbyFTE6zszbBRUvGWnyE71Kz")
            .unwrap()
            .0,
        AccountAddress2::from_str("3DkVqTDUkpLsX5tjyZmr2oLyjbhm8ogyCo9kzn2hjaF1ssLJBs")
            .unwrap()
            .0,
        AccountAddress2::from_str("399EHaAqiBhwDq5r9gM2tMLRc1pW3Xhsa4TPgsKEeceNjur6Fg")
            .unwrap()
            .0,
        AccountAddress2::from_str("2ydSporJThjG96iQmWt27o9tsr9DP6J83uFh87cEkb2eTWXmqt")
            .unwrap()
            .0,
        AccountAddress2::from_str("3dogiXxVSzT45o3gDf34NbB2qSXeiUXTJiw7jQJzEiZEgumELr")
            .unwrap()
            .0,
        AccountAddress2::from_str("4EmBCUFB4SvJ9tGe1mGqmDrqYzvYhgqUF7ZthgFTkTjdvzQZKj")
            .unwrap()
            .0,
        AccountAddress2::from_str("3jAoD6JKzENTa8WdDbgY1bYJnAKXbfc9u1mJkC7dQGqfEiJjRo")
            .unwrap()
            .0,
        AccountAddress2::from_str("4JiCVseYuWm3xWqpEj3gjAQHtpF7R7pgJhZ7RcEKemP1bL6Pjf")
            .unwrap()
            .0,
        AccountAddress2::from_str("4jQKMqxe9uENkx8s3SUkj2TKLGtEJtWeMBc9t2qKa21Y49yBjK")
            .unwrap()
            .0,
        AccountAddress2::from_str("3qTURAUi4k5LqBuDrLRu5n2qqy772HcQMj4MiMo5KgrUmRYiZ9")
            .unwrap()
            .0,
        AccountAddress2::from_str("4ak2PL3ELyKxVQSGX2d9tmihcpLVVfX9u2qtpwfPFPgjBxnGXu")
            .unwrap()
            .0,
        AccountAddress2::from_str("3VuSdUPCLnEx7hgW2PdioXxr6r8A4PSb2pjdPx9Qs9y3426t4t")
            .unwrap()
            .0,
        AccountAddress2::from_str("3szKe7DeLF19Z9VmYKsiVCnYn2zwHtyGAMfePN9s39LwhJfHvh")
            .unwrap()
            .0,
        AccountAddress2::from_str("3qpqBxRYYXLrUeXYsu5L5yMQ2uyqmaoYQ8aLXY871ZkXsMYVE9")
            .unwrap()
            .0,
        AccountAddress2::from_str("46qbxUp9JB5fYz36Q5ecrkVkatub1QTkarfrbxFFR4mMQWK1FM")
            .unwrap()
            .0,
        AccountAddress2::from_str("31PCt8bC5PDVbgFrypdQEMDvekpDZF2TA3vcCPkDeEdjWGTPer")
            .unwrap()
            .0,
        AccountAddress2::from_str("44s2udf7Ls4R8W3xDTJtR6HPeuSZTTaRPA5EJjvTF7Fn8svBeH")
            .unwrap()
            .0,
        AccountAddress2::from_str("3FEof7FzDHJ6FFnzTo4zeHv8gE2i6iJX5uLtWArtDDGA1sWJR2")
            .unwrap()
            .0,
        AccountAddress2::from_str("4pZP73WrnWmU7KeKBLRFexM2jMHN1y2mrbNaHssW3Q9WfTFjrz")
            .unwrap()
            .0,
        AccountAddress2::from_str("2xxvgHh99puU2WkLXSiyuWNPEnk4T5jKPtCdRZJRcJikPQnCsb")
            .unwrap()
            .0,
        AccountAddress2::from_str("4pLpayFj8QjT5sxHpUno2RT7Dt7AQ8YafTpDmX1DimD7t1kFkZ")
            .unwrap()
            .0,
        AccountAddress2::from_str("4HXGL81NCp4tfokz4aeC2YFcP9Xsq8GtwzPmgVqWPvAAiNeVp9")
            .unwrap()
            .0,
        AccountAddress2::from_str("3hNRjCez6if6HiWyFzwCZeus6rXoGqvYK7uQDD7zRwTXLgcUAu")
            .unwrap()
            .0,
        AccountAddress2::from_str("3qxnTWhA7GM9v6ND9koWkzTzve93orudRhViM8LE7qLNzGeeix")
            .unwrap()
            .0,
        AccountAddress2::from_str("4Wz53dG9dqvc3hUs2FSk1DMieNC8Mk3EQQxwjoc6exmFj7Bd57")
            .unwrap()
            .0,
        AccountAddress2::from_str("4WuWh8hsJbeSocCjHRY1sD7DEBz21BgxapAatPFdVaZ3tza7yy")
            .unwrap()
            .0,
        AccountAddress2::from_str("3kwJKxLRTqhTD9GHV5cXTa4tMceid1zD4kqv8H7zkj8cRe6exp")
            .unwrap()
            .0,
    ];

    let merkle_tree = lib::create_merkle_tree(&voter_accounts);
    let root = merkle_tree
        .root_hex()
        .ok_or("Couldn't get the merkle root")
        .unwrap();

    // Voteconfig as json
    let json = json!({
        "merkle_root": root,
        "merkle_leaf_count": merkle_tree.leaves_len(),
        "voting_question": "Vote for x",
        "deposit": "1000000",
        "registration_timeout": "2022-05-26T23:05:01Z",
        "commit_timeout": "2022-05-26T23:06:01Z",
        "vote_timeout": "2022-05-26T23:07:01Z"
    });

    std::fs::write(
        "../voting/parameters/voteconfig.json",
        serde_json::to_string_pretty(&json).unwrap(),
    )?;

    Ok((merkle_tree, voter_accounts))
}

/// Generates (x, g_x) and uses them to create register messages as binaries
pub fn make_register_msg(
    merkle_tree: MerkleTree<merkle_sha256>,
    accounts: Vec<AccountAddress>,
) -> std::io::Result<(Vec<Scalar>, Vec<ProjectivePoint>)> {
    let mut list_of_scalar: Vec<Scalar> = Vec::new();
    let mut list_of_voting_keys: Vec<ProjectivePoint> = Vec::new();

    for i in 0..40 as usize {
        let (x, g_x) = lib::create_votingkey_pair();
        let schnorr = lib::create_schnorr_zkp(g_x, x);

        fs::create_dir_all("../voting/parameters/register_msgs")?;

        let file_name = format!("../voting/parameters/register_msgs/register_msg{}.bin", i);
        let mut file = File::create(file_name)?;

        let register_msg = RegisterMessage {
            voting_key: g_x.to_bytes().to_vec(),
            voting_key_zkp: schnorr,
            merkle_proof: lib::create_merkle_proof(accounts[i], &merkle_tree),
        };

        list_of_scalar.push(x);
        list_of_voting_keys.push(g_x);

        file.write_all(&to_bytes(&register_msg))?;
    }
    Ok((list_of_scalar, list_of_voting_keys))
}

/// Generates reconstructed keys and vote commitments to create commit messages as binaries
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

/// Generates vote and its one-in-two ZKP to create vote messages as binaries
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
