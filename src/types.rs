use concordium_std::*;

/// Common types

// Phase timeouts
pub type RegistrationTimeout = Timestamp;
pub type PrecommitTimeout = Timestamp;
pub type CommitTimeout = Timestamp;
pub type VoteTimeout = Timestamp;

// Encrypted vote as commitment
pub type Commitment = Vec<u8>;
