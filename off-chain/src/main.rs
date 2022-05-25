
// use off_chain::*;
// use concordium_std::to_bytes;
// use std::env;
// use std::fs::File;
// use std::io::{Write, BufReader, BufRead, Error};
// use group::GroupEncoding;

// pub fn main() -> Result<(), Error>{
//     let path = "crypto.txt";
//     let mut output = File::create(path)?;

//     let args: Vec<String> = env::args().collect();

//     match args[1].as_str() {
//         "create_votingkey_pair" => {
//             let (x, g_x) = create_votingkey_pair();
//             write!(output,"x: {:?}\ng_x: {:?}", x.to_bytes().to_vec(), g_x.to_bytes().to_vec());
//         },  
//         "create_schnorr_zkp" => { 
//             let g_x = util::convert_vec_to_point(&args[2].as_bytes().to_vec());
//             let x = util::convert_vec_to_scalar(&args[3].as_bytes().to_vec());
//             let zkp = create_schnorr_zkp(g_x, x);
//             println!("{:?}", to_bytes(&zkp))
//         }
//         _ => ()
        
//     }
//     Ok(())
    

// }

pub mod lib;
use std::fs::File;
use std::io::prelude::*;
use serde_json::*;
use concordium_std::*;
use group::GroupEncoding;
use k256::{ProjectivePoint, Scalar};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use util::{hash_to_scalar, OneInTwoZKP, SchnorrProof};
use voting::*;

pub fn main() -> std::io::Result<()> {
    let (x, g_x) = lib::create_votingkey_pair();
    let schnorr = lib::create_schnorr_zkp(g_x, x);
    let mut file = File::create("register_msg3.bin")?;
    
    let register_msg = RegisterMessage {
        voting_key: g_x.to_bytes().to_vec(),
        voting_key_zkp: schnorr
    };

    file.write_all(&to_bytes(&register_msg))?;

    Ok(())
}