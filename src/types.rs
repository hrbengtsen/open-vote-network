use concordium_std::*;
use sha2::Sha256;
use curv::elliptic::curves::{Secp256k1};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof};
use serde::{Serialize, Deserialize};

/// Common types

// Phase timeouts
pub type RegistrationTimeout = Timestamp;
pub type PrecommitTimeout = Timestamp;
pub type CommitTimeout = Timestamp;
pub type VoteTimeout = Timestamp;

// g^y
pub type ReconstructedKey = Vec<u8>;

// Encrypted vote as commitment
pub type Commitment = Vec<u8>;

// Wrapper type for discrete log ZKP with Serialize concordium trait
#[derive(Serialize, Deserialize, Clone)]
pub struct DLogProofWrapper(pub DLogProof<Secp256k1, Sha256>);

impl Serial for DLogProofWrapper {
  fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
    let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
    out.write_all(&encoded)
  }
}

impl Deserial for DLogProofWrapper {
  fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
    source.get()
  }
}
