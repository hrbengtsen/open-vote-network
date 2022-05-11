//! A Rust crate for the main *voting* Concordium smart contract.
//!
//! It implements the Open Vote Network protocol using the elliptic curve *secp256k1*.
//! The protocol allows for decentralized privacy-preserving online voting, as defined here: http://homepages.cs.ncl.ac.uk/feng.hao/files/OpenVote_IET.pdf

use concordium_std::{collections::*, *};
use k256::elliptic_curve::PublicKey;
use k256::Secp256k1;
use util::{convert_vec_to_point, OneInTwoZKP, SchnorrProof};

pub mod crypto;
pub mod tests;
pub mod types;

// Contract structs

#[derive(Serialize, SchemaType)]
pub struct VoteConfig {
    authorized_voters: Vec<AccountAddress>,
    voting_question: String,
    deposit: Amount,
    registration_timeout: types::RegistrationTimeout,
    commit_timeout: types::CommitTimeout,
    vote_timeout: types::VoteTimeout,
}

#[derive(Serialize, SchemaType)]
struct RegisterMessage {
    voting_key: Vec<u8>,          // g^x
    voting_key_zkp: SchnorrProof, // zkp for x
}

#[derive(Serialize, SchemaType)]
struct CommitMessage {
    reconstructed_key: Vec<u8>, // g^y
    commitment: Vec<u8>,        // H(g^y*g^xv)
}

#[derive(Serialize, SchemaType)]
struct VoteMessage {
    vote: Vec<u8>,         // g^y*g^xv, v = {0, 1}
    vote_zkp: OneInTwoZKP, // one-in-two zkp for v
}

// Contract state
#[contract_state(contract = "voting")]
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
    voting_key_zkp: SchnorrProof,
    reconstructed_key: Vec<u8>,
    commitment: Vec<u8>,
    vote: Vec<u8>,
    vote_zkp: OneInTwoZKP,
}

// Contract functions

/// SETUP PHASE: create an instance of the contract with a voting config
#[init(contract = "voting", parameter = "VoteConfig")]
fn setup(ctx: &impl HasInitContext) -> Result<VotingState, types::SetupError> {
    let vote_config: VoteConfig = ctx.parameter_cursor().get()?;

    // Ensure config is valid
    ensure!(
        vote_config.registration_timeout > ctx.metadata().slot_time(),
        types::SetupError::InvalidRegistrationTimeout
    );
    ensure!(
        vote_config.commit_timeout > vote_config.registration_timeout,
        types::SetupError::InvalidPrecommitTimeout
    );
    ensure!(
        vote_config.vote_timeout > vote_config.commit_timeout,
        types::SetupError::InvalidVoteTimeout
    );
    ensure!(
        vote_config.deposit >= Amount::zero(),
        types::SetupError::NegativeDeposit
    );

    // Allow only >2 voters
    ensure!(
        vote_config.authorized_voters.len() > 2,
        types::SetupError::InvalidNumberOfVoters
    );

    // Set initial state
    let state = VotingState {
        config: vote_config,
        voting_phase: types::VotingPhase::Registration,
        voting_result: (-1, -1), // -1 = no result yet
        voters: BTreeMap::new(),
    };

    // Go through authorized voters and add an entry with default struct in voters map
    //for auth_voter in state.config.authorized_voters.clone() {
    //    state.voters.insert(auth_voter, Default::default());
    //}

    // Return success with initial voting state
    Ok(state)
}

// REGISTRATION PHASE: function voters call to register them for the vote by sending (voting key, ZKP, deposit)
#[receive(
    contract = "voting",
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
        state.config.authorized_voters.contains(&sender_address),
        types::RegisterError::UnauthorizedVoter
    );
    ensure!(
        state.config.deposit == deposit,
        types::RegisterError::WrongDeposit
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.registration_timeout,
        types::RegisterError::PhaseEnded
    );

    // Register the voter in the map, ensure they can only do this once
    match state.voters.get(&sender_address) {
        Some(_) => bail!(types::RegisterError::AlreadyRegistered),
        None => state.voters.insert(sender_address, Default::default()),
    };
    // Get the inserted voter
    let mut voter = util::unwrap_abort(state.voters.get_mut(&sender_address));

    // Check voting key (g^x) is valid point on curve, by attempting to convert
    match PublicKey::<Secp256k1>::from_sec1_bytes(&register_message.voting_key) {
        Ok(p) => p,
        Err(_) => bail!(types::RegisterError::InvalidVotingKey),
    };

    // Check validity of ZKP
    let zkp: SchnorrProof = register_message.voting_key_zkp.clone();
    ensure!(
        crypto::verify_schnorr_zkp(convert_vec_to_point(&register_message.voting_key), zkp),
        types::RegisterError::InvalidZKP
    );

    // Add register message to correct voter (i.e. voting key and zkp)
    voter.voting_key = register_message.voting_key;
    voter.voting_key_zkp = register_message.voting_key_zkp;

    // Check if all eligible voters has registered and automatically move to next phase if so
    if state.voters.len() == state.config.authorized_voters.len() {
        state.voting_phase = types::VotingPhase::Commit;
    }

    Ok(A::accept())
}

// COMMIT PHASE: function voters call to submit reconstructed key and commit to their vote (by sending a hash of it)
#[receive(contract = "voting", name = "commit", parameter = "CommitMessage")]
fn commit<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, types::CommitError> {
    let commitment_message: CommitMessage = ctx.parameter_cursor().get()?;

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

    // Save voters reconstructed key in voter state
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(types::CommitError::VoterNotFound),
    };
    voter.reconstructed_key = commitment_message.reconstructed_key;

    // Save voters commitment in voter state
    voter.commitment = commitment_message.commitment;

    // Check if all voters have submitted reconstructed key and committed to their vote. If so automatically move to next phase
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.reconstructed_key != Vec::<u8>::new() && v.commitment != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Vote;
    }

    Ok(A::accept())
}

// VOTE PHASE: function voters call to send their encrypted vote along with a one-in-two ZKP
#[receive(contract = "voting", name = "vote", parameter = "VoteMessage")]
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
    ensure!(
        voter.vote == Vec::<u8>::new(),
        types::VoteError::AlreadyVoted
    );

    // Verify one-in-two ZKP
    ensure!(
        crypto::verify_one_in_two_zkp(
            vote_message.vote_zkp.clone(),
            convert_vec_to_point(&voter.reconstructed_key)
        ),
        types::VoteError::InvalidZKP
    );

    // Check commitment matches vote
    ensure!(
        crypto::check_commitment(
            convert_vec_to_point(&vote_message.vote),
            voter.commitment.clone()
        ),
        types::VoteError::VoteCommitmentMismatch
    );

    // Set vote, zkp
    voter.vote = vote_message.vote;
    voter.vote_zkp = vote_message.vote_zkp;

    // Check all voters have voted and automatically move to next phase if so
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
#[receive(contract = "voting", name = "result")]
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
    votes.extend(
        state
            .voters
            .clone()
            .into_iter()
            .map(|(_, v)| convert_vec_to_point(&v.vote)),
    );

    // Brute force the tally (number of yes votes)
    let yes_votes = crypto::brute_force_tally(votes.clone());

    // Calc no votes
    let no_votes = votes.len() as i32 - yes_votes;

    // Set voting result in public state
    state.voting_result = (yes_votes, no_votes);

    Ok(A::accept())
}

// CHANGE PHASE: function anyone can call to change voting phase if conditions are met
#[receive(contract = "voting", name = "change_phase")]
fn change_phase<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> ReceiveResult<A> {
    let now = ctx.metadata().slot_time();

    match state.voting_phase {
        types::VotingPhase::Registration => {
            // Change to commit phase if registration time is over and atleast 3 voters have registered
            // Note: will move on with the vote without stalling/too slow authorized voters
            if now > state.config.registration_timeout
                && state
                    .voters
                    .clone()
                    .into_iter()
                    .filter(|(_, v)| v.voting_key != Vec::<u8>::new())
                    .count()
                    > 2
            {
                state.voting_phase = types::VotingPhase::Commit
            }
            // Change to abort if <3 voters have registered and time is over
            else if now > state.config.registration_timeout {
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Commit => {
            // Change to vote phase, if all voters have committed
            if state.voters.clone().into_iter().all(|(_, v)| {
                v.reconstructed_key != Vec::<u8>::new() && v.commitment != Vec::<u8>::new()
            }) {
                state.voting_phase = types::VotingPhase::Vote
            }
            // Change to abort if all have not committed and commit time is over
            else if now > state.config.commit_timeout {
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Vote => {
            // Change to result phase, if all voters have voted
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
        _ => (), // Handles abort and result phases which we can't move on from
    };
    Ok(A::accept())
}
