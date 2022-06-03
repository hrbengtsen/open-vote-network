//! A Rust crate for the main *voting* Concordium smart contract.
//!
//! It implements the Open Vote Network protocol using the elliptic curve *secp256k1*.
//! The protocol allows for decentralized privacy-preserving online voting, as defined here: http://homepages.cs.ncl.ac.uk/feng.hao/files/OpenVote_IET.pdf

use concordium_std::*;
use group::GroupEncoding;
use k256::elliptic_curve::PublicKey;
use k256::Secp256k1;
use util::{convert_vec_to_point, OneInTwoZKP, SchnorrProof};

pub mod crypto;
pub mod tests;
pub mod types;

// Contract structs

#[derive(Serialize, SchemaType)]
pub struct VoteConfig {
    merkle_root: String,
    merkle_leaf_count: i32,
    voting_question: String,
    deposit: Amount,
    registration_timeout: types::RegistrationTimeout,
    commit_timeout: types::CommitTimeout,
    vote_timeout: types::VoteTimeout,
}

#[derive(Serialize, SchemaType)]
pub struct RegisterMessage {
    pub voting_key: Vec<u8>,          // g^x
    pub voting_key_zkp: SchnorrProof, // zkp for x
    pub merkle_proof: util::MerkleProof,
}

#[derive(Serialize, SchemaType)]
pub struct CommitMessage {
    pub reconstructed_key: Vec<u8>, // g^y
    pub commitment: Vec<u8>,        // H(g^y*g^xv)
}

#[derive(Serialize, SchemaType)]
pub struct VoteMessage {
    pub vote: Vec<u8>,         // g^y*g^xv, v = {0, 1}
    pub vote_zkp: OneInTwoZKP, // one-in-two zkp for v
}

// Contract state
#[derive(Serial, DeserialWithState)]
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

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::RegisterError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        host.state().voting_phase == types::VotingPhase::Registration,
        types::RegisterError::NotRegistrationPhase
    );
    ensure!(
        host.state().config.deposit == deposit,
        types::RegisterError::WrongDeposit
    );
    ensure!(
        ctx.metadata().slot_time() <= host.state().config.registration_timeout,
        types::RegisterError::PhaseEnded
    );

    // Check voter is authorized through verifying merkle proof-of-membership
    ensure_eq!(
        crypto::verify_merkle_proof(
            &host.state().config.merkle_root,
            host.state().config.merkle_leaf_count,
            &register_message.merkle_proof,
            &sender_address
        ),
        Ok(true),
        types::RegisterError::UnauthorizedVoter
    );

    // Register the voter in the map, ensure they can only do this once
    match host.state().voters.get(&sender_address) {
        Some(_) => bail!(types::RegisterError::AlreadyRegistered),
        None => host
            .state_mut()
            .voters
            .insert(sender_address, Default::default()),
    };

    // Wrap in code block to scope host.state borrow
    {
        // Get the inserted voter
        let mut voter = util::unwrap_abort(host.state_mut().voters.get_mut(&sender_address));

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
    }

    // Check if all eligible voters has registered and automatically move to next phase if so
    if host.state().voters.iter().count() as i32 == host.state().config.merkle_leaf_count {
        host.state_mut().voting_phase = types::VotingPhase::Commit;
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

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::CommitError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        host.state().voting_phase == types::VotingPhase::Commit,
        types::CommitError::NotCommitPhase
    );
    ensure!(
        host.state().voters.get(&sender_address).is_some(),
        types::CommitError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= host.state().config.commit_timeout,
        types::CommitError::PhaseEnded
    );

    ensure!(
        commitment_message.commitment != Vec::<u8>::new(),
        types::CommitError::InvalidCommitMessage
    );
    ensure!(
        commitment_message.reconstructed_key != Vec::<u8>::new(),
        types::CommitError::InvalidCommitMessage
    );

    let mut keys = Vec::new();
    keys.extend(host.state().voters.iter().map(|(_,v)| convert_vec_to_point(&v.voting_key)));
    
    // Make sure committed reconstructed key is not the same as someone elses, e.g voter "stole" it from another to obstruct the tally



    // Save voter's reconstructed key and commitment in voter state
    match host.state_mut().voters.get_mut(&sender_address) {
        Some(mut v) => {
            ensure!(
                commitment_message.reconstructed_key == util::compute_reconstructed_key(&keys, convert_vec_to_point(&v.voting_key)).to_bytes().to_vec(),
                types::CommitError::InvalidCommitMessage
            );
            v.reconstructed_key = commitment_message.reconstructed_key;
            v.commitment = commitment_message.commitment;
        }

        None => bail!(types::CommitError::VoterNotFound),
    };

    // Check if all voters have submitted reconstructed key and committed to their vote. If so automatically move to next phase
    if host
        .state()
        .voters
        .iter()
        .all(|(_, v)| v.commitment != Vec::<u8>::new() && v.reconstructed_key != Vec::<u8>::new())
    {
        host.state_mut().voting_phase = types::VotingPhase::Vote;
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

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::VoteError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        host.state().voting_phase == types::VotingPhase::Vote,
        types::VoteError::NotVotePhase
    );
    ensure!(
        host.state().voters.get(&sender_address).is_some(),
        types::VoteError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= host.state().config.vote_timeout,
        types::VoteError::PhaseEnded
    );

    // Get voter
    match host.state_mut().voters.get_mut(&sender_address) {
        Some(mut v) => {
            // Ensure that voters cannot change their vote (cannot call vote function multiple times)
            ensure!(v.vote == Vec::<u8>::new(), types::VoteError::AlreadyVoted);

            // Verify one-in-two ZKP
            ensure!(
                crypto::verify_one_in_two_zkp(
                    vote_message.vote_zkp.clone(),
                    convert_vec_to_point(&v.reconstructed_key)
                ),
                types::VoteError::InvalidZKP
            );

            // Check commitment matches vote
            ensure!(
                crypto::check_commitment(
                    convert_vec_to_point(&vote_message.vote),
                    v.commitment.clone()
                ),
                types::VoteError::VoteCommitmentMismatch
            );

            // Set vote, zkp
            v.vote = vote_message.vote;
            v.vote_zkp = vote_message.vote_zkp;
        }
        None => bail!(types::VoteError::VoterNotFound),
    };

    // Check all voters have voted and automatically move to next phase if so
    if host
        .state()
        .voters
        .iter()
        .all(|(_, v)| v.vote != Vec::<u8>::new())
    {
        host.state_mut().voting_phase = types::VotingPhase::Result;
    }

    // Refund deposit to sender address (they have voted and their job is done)
    host.invoke_transfer(&sender_address, host.state().config.deposit)?;

    Ok(())
}

/// RESULT PHASE: function anyone can call to compute tally if vote is over
#[receive(contract = "voting", name = "result", mutable)]
fn result<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> Result<(i32, i32), types::ResultError> {
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

    Ok((yes_votes, no_votes))
}

/// CHANGE PHASE: function anyone can call to change voting phase if conditions are met
#[receive(contract = "voting", name = "change_phase", mutable)]
fn change_phase<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> Result<(), types::ChangeError> {
    let now = ctx.metadata().slot_time();
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(types::ChangeError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    match host.state().voting_phase {
        types::VotingPhase::Registration => {
            // Change to commit phase if registration time is over and atleast 3 voters have registered
            // Note: will move on with the vote without stalling/too slow authorized voters
            if now > host.state().config.registration_timeout
                && host
                    .state()
                    .voters
                    .iter()
                    .filter(|(_, v)| v.voting_key != Vec::<u8>::new())
                    .count()
                    > 2
            {
                host.state_mut().voting_phase = types::VotingPhase::Commit
            }
            // Change to abort if <3 voters have registered and time is over
            else if now > host.state().config.registration_timeout {
                refund_deposits(sender_address, host)?;
                host.state_mut().voting_phase = types::VotingPhase::Abort
            }
        }
        types::VotingPhase::Commit => {
            // Change to vote phase, if all voters have committed
            if host.state().voters.iter().all(|(_, v)| {
                v.reconstructed_key != Vec::<u8>::new() && v.commitment != Vec::<u8>::new()
            }) {
                host.state_mut().voting_phase = types::VotingPhase::Vote
            }
            // Change to abort if all have not committed and commit time is over
            else if now > host.state().config.commit_timeout {
                refund_deposits(sender_address, host)?;
                host.state_mut().voting_phase = types::VotingPhase::Abort
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
                host.state_mut().voting_phase = types::VotingPhase::Result
            }
            // Change to abort if vote time is over and not all have voted
            else if now > host.state().config.vote_timeout {
                refund_deposits(sender_address, host)?;
                host.state_mut().voting_phase = types::VotingPhase::Abort
            }
        }
        _ => (), // Handles abort and result phases which we can't move on from
    };
    Ok(())
}

/// Function to refund deposits, in case of the vote aborting. It penalizes stalling/malicious voters, refunds honest and rewards the change_phase caller who found out that we needed to abort
fn refund_deposits<S: HasStateApi>(
    sender: AccountAddress,
    host: &mut impl HasHost<VotingState<S>, StateApiType = S>,
) -> Result<(), TransferError> {
    // Number of voters registered for the vote
    let number_of_voters = host.state().voters.iter().count() as u64;

    // Get account list of the voters who stalled the vote
    let stalling_accounts: Vec<AccountAddress> = match host.state().voting_phase {
        types::VotingPhase::Registration => {
            let mut stalling_accounts = Vec::<AccountAddress>::new();
            for (addr, voter) in host.state().voters.iter() {
                if voter.voting_key == Vec::<u8>::new() {
                    stalling_accounts.push(*addr);
                }
            }
            stalling_accounts
        }
        types::VotingPhase::Commit => {
            let mut stalling_accounts = Vec::<AccountAddress>::new();
            for (addr, voter) in host.state().voters.iter() {
                if voter.reconstructed_key == Vec::<u8>::new() {
                    stalling_accounts.push(*addr);
                }
            }
            stalling_accounts
        }
        types::VotingPhase::Vote => {
            let mut stalling_accounts = Vec::<AccountAddress>::new();
            for (addr, voter) in host.state().voters.iter() {
                if voter.vote == Vec::<u8>::new() {
                    stalling_accounts.push(*addr);
                }
            }
            stalling_accounts
        }
        // Impossible case
        _ => trap(),
    };

    // Get account list of the honest voters
    let honest_accounts: Vec<AccountAddress> = match host.state().voting_phase {
        types::VotingPhase::Registration => {
            let mut honest_accounts = Vec::<AccountAddress>::new();
            for (addr, voter) in host.state().voters.iter() {
                if voter.voting_key != Vec::<u8>::new() {
                    honest_accounts.push(*addr);
                }
            }
            honest_accounts
        }
        types::VotingPhase::Commit => {
            let mut honest_accounts = Vec::<AccountAddress>::new();
            for (addr, voter) in host.state().voters.iter() {
                if voter.reconstructed_key != Vec::<u8>::new() {
                    honest_accounts.push(*addr);
                }
            }
            honest_accounts
        }
        types::VotingPhase::Vote => {
            let mut honest_accounts = Vec::<AccountAddress>::new();
            for (addr, voter) in host.state().voters.iter() {
                if voter.vote != Vec::<u8>::new() {
                    honest_accounts.push(*addr);
                }
            }
            honest_accounts
        }
        // Impossible case
        _ => trap(),
    };

    // Reward sender (caller of change_phase) if they are not a stalling voter and there were honest voters
    if !stalling_accounts.contains(&sender) && number_of_voters - honest_accounts.len() as u64 > 0 {
        host.invoke_transfer(&sender, host.state().config.deposit)?;
    }

    // Go through all honest voters and refund their deposit
    if host.state().voting_phase != types::VotingPhase::Vote {
        for account in honest_accounts {
            host.invoke_transfer(&account, host.state().config.deposit)?;
        }
    }

    Ok(())
}
