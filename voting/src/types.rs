use concordium_std::*;

/// Common types

// Phase timeouts
pub type RegistrationTimeout = Timestamp;
pub type PrecommitTimeout = Timestamp;
pub type CommitTimeout = Timestamp;
pub type VoteTimeout = Timestamp;

/// Enums

#[derive(Serialize, PartialEq, SchemaType)]
pub enum VotingPhase {
    Registration,
    Precommit,
    Commit,
    Vote,
    Result,
    Abort,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum SetupError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Invalid timeouts (in the past or not later than the previous one)
    InvalidRegistrationTimeout,
    InvalidPrecommitTimeout,
    InvalidCommitTimeout,
    InvalidVoteTimeout,
    // Deposits should be >=0
    NegativeDeposit,
    // Must have atleast 3 voters
    InvalidNumberOfVoters,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum RegisterError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Only allow authorized voters
    UnauthorizedVoter,
    // Sender cannot be contract
    ContractSender,
    // Deposit does not equal the required amount
    WrongDeposit,
    // Not in registration phase
    NotRegistrationPhase,
    // Registration phase has ended
    PhaseEnded,
    // Voter not found
    VoterNotFound,
    // Voter is already registered
    AlreadyRegistered,
    // Invalid ZKP
    InvalidZKP,
    // Invalid voting key (not valid ECC point)
    InvalidVotingKey,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum PrecommitError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Only allow authorized voters
    UnauthorizedVoter,
    // Sender cannot be contract
    ContractSender,
    // Not in precommit phase
    NotPrecommitPhase,
    // Precommit phase has ended
    PhaseEnded,
    // Voter was not found
    VoterNotFound,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum CommitError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Only allow authorized voters
    UnauthorizedVoter,
    // Sender cannot be contract
    ContractSender,
    // Not in Commit phase
    NotCommitPhase,
    // Commit phase has ended
    PhaseEnded,
    // Voter was not found
    VoterNotFound,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum VoteError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Only allow authorized voters
    UnauthorizedVoter,
    // Sender cannot be contract
    ContractSender,
    // Not in Vote phase
    NotVotePhase,
    // Commit phase has ended
    PhaseEnded,
    // Voter was not found
    VoterNotFound,
    // ZKP not correct
    InvalidZKP,
    // Mismatch between vote and commitment to vote
    VoteCommitmentMismatch,
    // Voter already voted
    AlreadyVoted,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum ResultError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Not in result phase
    NotResultPhase,
}
