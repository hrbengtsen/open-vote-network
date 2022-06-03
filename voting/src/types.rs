//! Rust file containing common types and enums used in the *voting* contract.

use concordium_std::*;

/// Common types
pub type RegistrationTimeout = Timestamp;
pub type CommitTimeout = Timestamp;
pub type VoteTimeout = Timestamp;

/// Enums

#[derive(Serialize, PartialEq, SchemaType, Debug)]
pub enum VotingPhase {
    Registration,
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
    // Account cannot confirm registration
    AccountSender,
    // Not the right contract
    InvalidContractSender,
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
    // Something in CommitMessage is just an empty vector
    InvalidCommitMessage,
}

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum VoteError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Failed doing transfer
    #[from(TransferError)]
    DoTransfer,
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

#[derive(Debug, PartialEq, Eq, Reject)]
pub enum ChangeError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Contracts cannot change phase
    ContractSender,
    #[from(TransferError)]
    TransferRefund,
}
