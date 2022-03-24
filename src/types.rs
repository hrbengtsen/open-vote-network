use concordium_std::*;

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
