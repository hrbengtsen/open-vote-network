//#![no_std]

use concordium_std::{collections::*, *};
//use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
//use curv::elliptic::curves::{Point, Secp256k1};

// TODO: REMEBER TO CHECK FOR ABORT CASE IN ALL FUNCTIONS

pub mod crypto;
pub mod types;
pub mod tests;

/// Contract structs

#[derive(Serialize, SchemaType)]
pub struct VoteConfig {
    authorized_voters: Vec<AccountAddress>,
    voting_question: String,
    deposit: Amount,
    registration_timeout: types::RegistrationTimeout,
    precommit_timeout: types::PrecommitTimeout,
    commit_timeout: types::CommitTimeout,
    vote_timeout: types::VoteTimeout,
}

#[derive(Serialize, SchemaType)]
struct RegisterMessage {
    voting_key: Vec<u8>,     // g^x
    voting_key_zkp: Vec<u8>, // zkp for x
}

#[derive(Serialize)]
struct ReconstructedKey(Vec<u8>); // g^y

#[derive(Serialize)]
struct Commitment(Vec<u8>);

#[derive(Serialize, Default, PartialEq, Clone)]
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

#[derive(Serialize, SchemaType)]
struct VoteMessage {
    vote: Vec<u8>,         // v = {0, 1}
    vote_zkp: OneInTwoZKP, // one-in-two zkp for v
}

// Contract state
#[contract_state(contract = "open_vote_network")]
#[derive(Serialize, SchemaType)]
pub struct VotingState {
    config: VoteConfig,
    voting_phase: types::VotingPhase,
    voting_result: (i32, i32),
    voters: BTreeMap<AccountAddress, Voter>,
}

#[derive(Serialize, SchemaType, Clone, PartialEq, Default)]
struct Voter {
    voting_key: Vec<u8>,
    voting_key_zkp: Vec<u8>,
    reconstructed_key: Vec<u8>,
    commitment: Vec<u8>,
    vote: Vec<u8>,
    vote_zkp: OneInTwoZKP,
}

/// Contract functions

// SETUP PHASE: function to create an instance of the contract with a voting config as parameter
#[init(contract = "open_vote_network", parameter = "VoteConfig")]
fn setup(ctx: &impl HasInitContext) -> Result<VotingState, types::SetupError> {
    let vote_config: VoteConfig = ctx.parameter_cursor().get()?;

    // Ensure config is valid
    ensure!(
        vote_config.registration_timeout > ctx.metadata().slot_time(),
        types::SetupError::InvalidRegistrationTimeout
    );
    ensure!(
        vote_config.precommit_timeout > vote_config.registration_timeout,
        types::SetupError::InvalidPrecommitTimeout
    );
    ensure!(
        vote_config.commit_timeout > vote_config.precommit_timeout,
        types::SetupError::InvalidCommitTimeout
    );
    ensure!(
        vote_config.vote_timeout > vote_config.commit_timeout,
        types::SetupError::InvalidVoteTimeout
    );
    ensure!(
        vote_config.deposit >= Amount::zero(),
        types::SetupError::NegativeDeposit
    );
    ensure!(
        vote_config.authorized_voters.len() > 2,
        types::SetupError::InvalidNumberOfVoters
    );
    // possibly more ensures for better user experience..

    // Set initial state
    let mut state = VotingState {
        config: vote_config,
        voting_phase: types::VotingPhase::Registration,
        voting_result: (-1, -1), // -1 = no result yet
        voters: BTreeMap::new(),
    };

    // Go through authorized voters and add an entry with default struct in voters map
    for auth_voter in state.config.authorized_voters.clone() {
        state.voters.insert(auth_voter, Default::default());
    }

    // Return success with initial voting state
    Ok(state)
}
/*
// REGISTRATION PHASE: function voters call to register them for the vote by sending (voting key, ZKP, deposit)
#[receive(
    contract = "open_vote_network",
    name = "register",
    parameter = "RegisterMessage",
    payable
)]
fn register<A: HasActions>(
    ctx: &impl HasReceiveContext,
    deposit: Amount,
    state: &mut VotingState,
) -> Result<A, types::RegisterError> {
    let register_message: RegisterMessage = ctx.parameter_cursor().get()?;

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::RegisterError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == types::VotingPhase::Registration,
        types::RegisterError::NotRegistrationPhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        types::RegisterError::UnauthorizedVoter
    );
    ensure!(state.config.deposit == deposit, types::RegisterError::WrongDeposit);
    ensure!(
        ctx.metadata().slot_time() <= state.config.registration_timeout,
        types::RegisterError::PhaseEnded
    );

    // Ensure voters only register once
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(types::RegisterError::VoterNotFound),
    };
    ensure!(
        voter.voting_key == Vec::<u8>::new(),
        types::RegisterError::AlreadyRegistered
    );

    // Check voting key (g^x) is valid point on ECC
    let point = match Point::<Secp256k1>::from_bytes(&register_message.voting_key) {
        Ok(p) => p,
        Err(_) => bail!(types::RegisterError::InvalidVotingKey),
    };
    match point.ensure_nonzero() {
        Ok(_) => (),
        Err(_) => bail!(types::RegisterError::InvalidVotingKey),
    }

    // Check validity of ZKP
    let decoded_proof: DLogProof<Secp256k1, Sha256> =
        serde_json::from_slice(&register_message.voting_key_zkp).unwrap();
    ensure!(
        crypto::verify_dl_zkp(decoded_proof),
        types::RegisterError::InvalidZKP
    );

    // Add register message to correct voter (i.e. voting key and zkp)
    voter.voting_key = register_message.voting_key;
    voter.voting_key_zkp = register_message.voting_key_zkp;

    // Check if all eligible voters has registered
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.voting_key != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Precommit;
    }

    Ok(A::accept())
}

// PRECOMMIT PHASE: function voters call to send reconstructed key
#[receive(
    contract = "open_vote_network",
    name = "precommit",
    parameter = "ReconstructedKey"
)]
fn precommit<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, types::PrecommitError> {
    let reconstructed_key: ReconstructedKey = ctx.parameter_cursor().get()?;

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::PrecommitError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == types::VotingPhase::Precommit,
        types::PrecommitError::NotPrecommitPhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        types::PrecommitError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.precommit_timeout,
        types::PrecommitError::PhaseEnded
    );

    // Save voters reconstructed key in voter state
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(types::PrecommitError::VoterNotFound),
    };
    voter.reconstructed_key = reconstructed_key.0;

    // Check if all voters have submitted their reconstructed key
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.reconstructed_key != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Commit;
    }

    Ok(A::accept())
}

// COMMIT PHASE: function voters call to commit to their vote (by sending a hash of it)
#[receive(
    contract = "open_vote_network",
    name = "commit",
    parameter = "Commitment"
)]
fn commit<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, types::CommitError> {
    let commitment: Commitment = ctx.parameter_cursor().get()?;

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::CommitError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == types::VotingPhase::Commit,
        types::CommitError::NotCommitPhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        types::CommitError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.commit_timeout,
        types::CommitError::PhaseEnded
    );

    // Save voters commitment in voter state
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(types::CommitError::VoterNotFound),
    };
    voter.commitment = commitment.0;

    // Check if all voters have committed to their vote
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.commitment != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Vote;
    }

    Ok(A::accept())
}

// VOTE PHASE: function voters call to send they encrypted vote along with a one-out-of-two ZKP
#[receive(
    contract = "open_vote_network",
    name = "vote",
    parameter = "VoteMessage"
)]
fn vote<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, types::VoteError> {
    let vote_message: VoteMessage = ctx.parameter_cursor().get()?;

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::VoteError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == types::VotingPhase::Vote,
        types::VoteError::NotVotePhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        types::VoteError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.vote_timeout,
        types::VoteError::PhaseEnded
    );

    // Get voter
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(types::VoteError::VoterNotFound),
    };

    // Ensure that voters cannot change their vote (cannot call vote function multiple times)
    ensure!(voter.vote == Vec::<u8>::new(), types::VoteError::AlreadyVoted);

    // Verify one-out-of-two ZKP
    ensure!(
        crypto::verify_one_out_of_two_zkp(
            vote_message.vote_zkp.clone(),
            Point::<Secp256k1>::from_bytes(&voter.reconstructed_key).unwrap()
        ),
        types::VoteError::InvalidZKP
    );

    // Check commitment matches vote
    ensure!(
        crypto::check_commitment(
            Point::<Secp256k1>::from_bytes(&vote_message.vote).unwrap(),
            voter.commitment.clone()
        ),
        types::VoteError::VoteCommitmentMismatch
    );

    // Set vote, zkp
    voter.vote = vote_message.vote;
    voter.vote_zkp = vote_message.vote_zkp;

    // Check all voters have voted
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.vote != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Result;
    }

    // Refund deposit to sender address (they have voted and their job is done)
    Ok(A::simple_transfer(&sender_address, state.config.deposit))
}

// RESULT PHASE: function anyone can call to compute tally if vote is over
#[receive(contract = "open_vote_network", name = "result")]
fn result<A: HasActions>(
    _ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, types::ResultError> {
    ensure!(
        state.voting_phase == types::VotingPhase::Result,
        types::ResultError::NotResultPhase
    );

    // Create list of all votes
    let mut votes = Vec::new();
    for (_, v) in state.voters.clone().into_iter() {
        votes.push(Point::<Secp256k1>::from_bytes(&v.vote).unwrap());
    }

    let yes_votes = crypto::brute_force_tally(votes.clone());
    let no_votes = votes.len() as i32 - yes_votes;

    state.voting_result = (yes_votes, no_votes);

    Ok(A::accept())
}

// CHANGE PHASE: function everyone can call to change voting phase if conditions are met
#[receive(contract = "open_vote_network", name = "change_phase")]
fn change_phase<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> ReceiveResult<A> {
    let now = ctx.metadata().slot_time();
    match state.voting_phase {
        types::VotingPhase::Registration => {
            // Change to precommit if register time is over
            if now > state.config.registration_timeout {
                state.voting_phase = types::VotingPhase::Precommit
            }
        }
        types::VotingPhase::Precommit => {
            // Change to commit if all voters have submitted g^y
            if state
                .voters
                .clone()
                .into_iter()
                .all(|(_, v)| v.reconstructed_key != Vec::<u8>::new())
            {
                state.voting_phase = types::VotingPhase::Commit
            } 
            // Change to abort if precommit time is over (and some have not submitted g^y)
            else if now > state.config.precommit_timeout {
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Commit => {
            // Change to vote if all voters have committed
            if state
                .voters
                .clone()
                .into_iter()
                .all(|(_, v)| v.commitment != Vec::<u8>::new())
            {
                state.voting_phase = types::VotingPhase::Vote
            } 
            // Change to abort if all have not committed and commit time is over
            else if now > state.config.commit_timeout {
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Vote => {
            // Change to result if all voters have voted
            if state
                .voters
                .clone()
                .into_iter()
                .all(|(_, v)| v.vote != Vec::<u8>::new())
            {
                state.voting_phase = types::VotingPhase::Result
            } 
            // Change to abort if vote time is over and not all have voted
            else if now > state.config.vote_timeout {
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        _ => (), // Handles abort and result phases which we cant move on from
    };
    Ok(A::accept())
}
*/