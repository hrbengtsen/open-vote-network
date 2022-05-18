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
#[derive(Serial, DeserialWithState, SchemaType)]
#[concordium(state_parameter = "S")]
pub struct VotingState<S> {
    config: VoteConfig,
    voting_phase: types::VotingPhase,
    voting_result: (i32, i32),
    voters: StateMap<AccountAddress, Voter, S>,
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
fn setup<S: HasStateApi>(
    ctx: &impl HasInitContext,
    state_builder: &mut StateBuilder<S>,
) -> Result<VotingState<S>, types::SetupError> {
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
        voters: state_builder.new_map(),
    };

    // Return success with initial voting state
    Ok(state)
}

/// REGISTRATION PHASE: function voters call to register them for the vote by sending (voting key, ZKP, deposit)
#[receive(
    contract = "voting",
    name = "register",
    parameter = "RegisterMessage",
    payable,
    mutable
)]
fn register<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
    deposit: Amount,
) -> Result<(), types::RegisterError> {
    let register_message: RegisterMessage = ctx.parameter_cursor().get()?;
    let mut state = host.state_mut();

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
        state
            .config
            .authorized_voters
            .contains(&sender_address),
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
        None => state
            .voters
            .insert(sender_address, Default::default()),
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
    if state.voters.iter().count() == state.config.authorized_voters.len() {
        state.voting_phase = types::VotingPhase::Commit;
    }

    Ok(())
}

/// COMMIT PHASE: function voters call to submit reconstructed key and commit to their vote (by sending a hash of it)
#[receive(
    contract = "voting",
    name = "commit",
    parameter = "CommitMessage",
    mutable
)]
fn commit<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> Result<(), types::CommitError> {
    let commitment_message: CommitMessage = ctx.parameter_cursor().get()?;
    let mut state = host.state_mut();

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::CommitError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        commitment_message.commitment != Vec::<u8>::new(),
        types::CommitError::InvalidCommitMessage
    );
    ensure!(
        commitment_message.reconstructed_key != Vec::<u8>::new(),
        types::CommitError::InvalidCommitMessage
    );
    ensure!(
        state.voting_phase == types::VotingPhase::Commit,
        types::CommitError::NotCommitPhase
    );
    ensure!(
        state.voters.get(&sender_address).is_some(),
        types::CommitError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.commit_timeout,
        types::CommitError::PhaseEnded
    );

    // Save voters reconstructed key in voter state
    let mut voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(types::CommitError::VoterNotFound),
    };
    voter.reconstructed_key = commitment_message.reconstructed_key;

    // Save voters commitment in voter state
    voter.commitment = commitment_message.commitment;

    // Check if all voters have submitted reconstructed key and committed to their vote. If so automatically move to next phase
    if state
        .voters
        .iter()
        .all(|(_, v)| v.reconstructed_key != Vec::<u8>::new() && v.commitment != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Vote;
    }

    Ok(())
}

/// VOTE PHASE: function voters call to send their encrypted vote along with a one-in-two ZKP
#[receive(contract = "voting", name = "vote", parameter = "VoteMessage", mutable)]
fn vote<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> Result<(), types::VoteError> {
    let vote_message: VoteMessage = ctx.parameter_cursor().get()?;
    let mut state = host.state_mut();

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
        state.voters.get(&sender_address).is_some(),
        types::VoteError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.vote_timeout,
        types::VoteError::PhaseEnded
    );

    // Get voter
    let mut voter = match state.voters.get_mut(&sender_address) {
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
        .iter()
        .all(|(_, v)| v.vote != Vec::<u8>::new())
    {
        state.voting_phase = types::VotingPhase::Result;
    }

    host.invoke_transfer(&sender_address, state.config.deposit);
    // Refund deposit to sender address (they have voted and their job is done)
    Ok(())
}

/// RESULT PHASE: function anyone can call to compute tally if vote is over
#[receive(contract = "voting", name = "result", mutable)]
fn result<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> Result<(), types::ResultError> {
    let mut state = host.state_mut();

    ensure!(
        state.voting_phase == types::VotingPhase::Result,
        types::ResultError::NotResultPhase
    );

    // Create list of all votes
    let mut votes = Vec::new();
    votes.extend(
        state
            .voters
            .iter()
            .map(|(_, v)| convert_vec_to_point(&v.vote)),
    );

    // Brute force the tally (number of yes votes)
    let yes_votes = crypto::brute_force_tally(votes.clone());

    // Calc no votes
    let no_votes = votes.len() as i32 - yes_votes;

    // Set voting result in public state
    state.voting_result = (yes_votes, no_votes);

    Ok(())
}

/// CHANGE PHASE: function anyone can call to change voting phase if conditions are met
#[receive(contract = "voting", name = "change_phase", mutable)]
fn change_phase<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> ReceiveResult<()> {
    let mut state = host.state_mut();

    let now = ctx.metadata().slot_time();
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(),
        Address::Account(account_address) => account_address,
    };

    match state.voting_phase {
        types::VotingPhase::Registration => {
            // Change to commit phase if registration time is over and atleast 3 voters have registered
            // Note: will move on with the vote without stalling/too slow authorized voters
            if now > state.config.registration_timeout
                && host
                    .state()
                    .voters
                    .iter()
                    .filter(|(_, v)| v.voting_key != Vec::<u8>::new())
                    .count()
                    > 2
            {
                state.voting_phase = types::VotingPhase::Commit
            }
            // Change to abort if <3 voters have registered and time is over
            else if now > state.config.registration_timeout {
                refund_deposits(sender_address, host);
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Commit => {
            // Change to vote phase, if all voters have committed
            if state.voters.iter().all(|(_, v)| {
                v.reconstructed_key != Vec::<u8>::new() && v.commitment != Vec::<u8>::new()
            }) {
                state.voting_phase = types::VotingPhase::Vote
            }
            // Change to abort if all have not committed and commit time is over
            else if now > state.config.commit_timeout {
                refund_deposits(sender_address, host);
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Vote => {
            // Change to result phase, if all voters have voted
            if host
                .state()
                .voters
                .iter()
                .all(|(_, v)| v.vote != Vec::<u8>::new())
            {
                state.voting_phase = types::VotingPhase::Result
            }
            // Change to abort if vote time is over and not all have voted
            else if now > state.config.vote_timeout {
                refund_deposits(sender_address, host);
                state.voting_phase = types::VotingPhase::Abort
            }
        }
        _ => (), // Handles abort and result phases which we can't move on from
    };
    Ok(())
}

/// Function to refund deposits, in case of the vote aborting. It evenly distributes the stalling voters deposits to the honest voters
fn refund_deposits<S: HasStateApi>(
    sender: AccountAddress,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> () {
    let mut state = host.state_mut();
    // Number of voters registered for the vote
    let number_of_voters = state.voters.iter().count() as u64;

    // Get account list of the voters who stalled the vote OBS! wrong! need to be different depending on VotingPhase
    let stalling_accounts: Vec<&AccountAddress> = match state.voting_phase {
        types::VotingPhase::Registration => state
            .voters
            .iter()
            .filter(|(_, v)| v.voting_key == Vec::<u8>::new())
            .map(|(a, _)| a)
            .fold(Vec::<&AccountAddress>::new(), |acc, a| {
                acc.push(&a);
                acc
            }),
        types::VotingPhase::Commit => state
            .voters
            .iter()
            .filter(|(_, v)| v.reconstructed_key == Vec::<u8>::new())
            .map(|(a, _)| a)
            .fold(Vec::<&AccountAddress>::new(), |acc, a| {
                acc.push(&a);
                acc
            }),
        types::VotingPhase::Vote => state
            .voters
            .iter()
            .filter(|(_, v)| v.vote == Vec::<u8>::new())
            .map(|(a, _)| a)
            .fold(Vec::<&AccountAddress>::new(), |acc, a| {
                acc.push(&a);
                acc
            }),
        // Impossible case
        _ => trap(),
    };

    let honest_accounts: Vec<&AccountAddress> = match state.voting_phase {
        types::VotingPhase::Registration => state
            .voters
            .iter()
            .filter(|(_, v)| v.voting_key != Vec::<u8>::new())
            .map(|(a, _)| a)
            .fold(Vec::<&AccountAddress>::new(), |acc, a| {
                acc.push(&a);
                acc
            }),
        types::VotingPhase::Commit => state
            .voters
            .iter()
            .filter(|(_, v)| v.reconstructed_key != Vec::<u8>::new())
            .map(|(a, _)| a)
            .fold(Vec::<&AccountAddress>::new(), |acc, a| {
                acc.push(&a);
                acc
            }),
        types::VotingPhase::Vote => state
            .voters
            .iter()
            .filter(|(_, v)| v.vote != Vec::<u8>::new())
            .map(|(a, _)| a)
            .fold(Vec::<&AccountAddress>::new(), |acc, a| {
                acc.push(&a);
                acc
            }),
        // Impossible case
        _ => trap(),
    };

    // The total amount of deposits from the stalling voters, to be distributed: 0 + (#stalling * deposit)
    let stalling_amount = Amount::from_micro_ccd(0)
        .add_micro_ccd(stalling_accounts.len() as u64 * state.config.deposit.micro_ccd);

    // Number of "honest" voters
    let number_of_honest = number_of_voters - stalling_accounts.len() as u64;

    // The extra amount each honest voter gets. The account that calls change_phase which results in an Abort will receive the remainder
    let (quotient_amount, remainder_amount) = if number_of_honest == 0 {
        (Amount::zero(), stalling_amount - Amount::from_micro_ccd(1))
    } else {
        stalling_amount.quotient_remainder(number_of_honest)
    };

    // Adding the deposit the voter paid in registration. Final amount honest voters will get
    let final_amount = state
        .config
        .deposit
        .add_micro_ccd(quotient_amount.micro_ccd);

    // All the transfer (refund) actions, initialize with first action of transfer of remainder to sender
    host.invoke_transfer(&sender, remainder_amount + final_amount);

    for i in 1..number_of_honest as usize {
        host.invoke_transfer(honest_accounts[i], final_amount);
    }
}
