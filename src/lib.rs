use concordium_std::{collections::*, *};
use curv::elliptic::curves::{Point, Secp256k1};
use sha2::Sha256;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof};

mod crypto;
mod types;

/// Contract enum and structs

#[derive(Serialize, PartialEq)]
enum VotingPhase {
    Registration,
    Precommit,
    Commit,
    Vote,
    Result,
}

#[derive(Serialize, SchemaType)]
struct VoteConfig {
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
    voting_key: Vec<u8>, // g^x
    voting_key_zkp: Vec<u8>, // zkp for x
}

#[derive(Serialize, Default, PartialEq, Clone)]
struct OneInTwoZKP {
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
    vote: Vec<u8>, // v = {0, 1}
    vote_zkp: OneInTwoZKP, // one-in-two zkp for v
}

// Contract state
#[contract_state(contract = "open_vote_network")]
#[derive(Serialize, SchemaType)]
pub struct VotingState {
    config: VoteConfig,
    voting_phase: VotingPhase,
    voting_result: i32,
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

#[derive(Debug, PartialEq, Eq, Reject)]
enum SetupError {
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
}

#[derive(Debug, PartialEq, Eq, Reject)]
enum RegisterError {
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
    InvalidVotingKey
}

/// Contract functions

// SETUP PHASE: function to create an instance of the contract with a voting config as parameter
#[init(contract = "open_vote_network", parameter = "VoteConfig")]
fn setup(ctx: &impl HasInitContext) -> Result<VotingState, SetupError> {
    let vote_config: VoteConfig = ctx.parameter_cursor().get()?;

    // Ensure config is valid
    ensure!(
        vote_config.registration_timeout > ctx.metadata().slot_time(),
        SetupError::InvalidRegistrationTimeout
    );
    ensure!(
        vote_config.precommit_timeout > vote_config.registration_timeout,
        SetupError::InvalidPrecommitTimeout
    );
    ensure!(
        vote_config.commit_timeout > vote_config.precommit_timeout,
        SetupError::InvalidCommitTimeout
    );
    ensure!(
        vote_config.vote_timeout > vote_config.commit_timeout,
        SetupError::InvalidVoteTimeout
    );
    ensure!(
        vote_config.deposit >= Amount::zero(),
        SetupError::NegativeDeposit
    );
    // possibly more ensures for better user experience..

    // Set initial state
    let mut state = VotingState {
        config: vote_config,
        voting_phase: VotingPhase::Registration,
        voting_result: -1, // -1 = no result yet
        voters: BTreeMap::new(),
    };

    // Go through authorized voters and add an entry with default struct in voters map
    for auth_voter in state.config.authorized_voters.clone() {
        state.voters.insert(auth_voter, Default::default());
    }

    // Return success with initial voting state
    Ok(state)
}

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
) -> Result<A, RegisterError> {
    let register_message: RegisterMessage = ctx.parameter_cursor().get()?;

    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(RegisterError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == VotingPhase::Registration,
        RegisterError::NotRegistrationPhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        RegisterError::UnauthorizedVoter
    );
    ensure!(
        state.config.deposit == deposit,
        RegisterError::WrongDeposit
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.registration_timeout,
        RegisterError::PhaseEnded
    );

    // Ensure voters only register once
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(RegisterError::VoterNotFound),
    };
    ensure!(
        voter.voting_key == Vec::<u8>::new(),
        RegisterError::AlreadyRegistered
    );

    // Check voting key (g^x) is valid point on ECC
    let point = match Point::<Secp256k1>::from_bytes(&register_message.voting_key) {
        Ok(p) => p,
        Err(_) => bail!(RegisterError::InvalidVotingKey)
    };
    match point.ensure_nonzero() {
        Ok(_) => (),
        Err(_) => bail!(RegisterError::InvalidVotingKey)
    }

    // Check validity of ZKP
    let decoded_proof: DLogProof<Secp256k1, Sha256> = serde_json::from_slice(&register_message.voting_key_zkp).unwrap();
    ensure!(
        crypto::verify_dl_zkp(decoded_proof.clone()),
        RegisterError::InvalidZKP
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
        state.voting_phase = VotingPhase::Precommit;
    }

    Ok(A::accept())
}

// PRECOMMIT PHASE: function voters call to send reconstructed key
#[receive(
    contract = "open_vote_network",
    name = "submit",
    parameter = "ReconstructedKey"
)]
fn submit_reconstructed_key<A: HasActions>(
    _ctx: &impl HasReceiveContext,
    _state: &mut VotingState,
) -> ReceiveResult<A> {
    // handle timeout, save voters reconstructed key in voter state
    todo!();
}

// COMMIT PHASE: function voters call to commit to their vote (by sending a hash of it)
#[receive(
    contract = "open_vote_network",
    name = "commit",
    parameter = "Commitment"
)]
fn commit<A: HasActions>(
    _ctx: &impl HasReceiveContext,
    _state: &mut VotingState,
) -> ReceiveResult<A> {
    todo!();
}

// VOTE PHASE: function voters call to send they encrypted vote along with a one-out-of-two ZKP
#[receive(
    contract = "open_vote_network",
    name = "vote",
    parameter = "VoteMessage"
)]
fn vote<A: HasActions>(
    _ctx: &impl HasReceiveContext,
    _state: &mut VotingState,
) -> ReceiveResult<A> {
    // handle timeout, saving vote, checking ZKP
    todo!();
}

// RESULT PHASE:
fn result() {
    todo!();
}

// A bunch of utility functions for crypto stuff, ZKPs, etc. should be made for the above functions, should be local and not on-contract?

// UNIT TESTS:
#[concordium_cfg_test]
mod tests {
    use super::*;
    use test_infrastructure::*;
    use curv::elliptic::curves::{Scalar};

    #[concordium_test]
    fn test_setup() {
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);

        let vote_config = VoteConfig {
            authorized_voters: vec![account1, account2],
            voting_question: "Vote for x".to_string(),
            deposit: Amount::from_micro_ccd(0),
            registration_timeout: Timestamp::from_timestamp_millis(100),
            precommit_timeout: Timestamp::from_timestamp_millis(200),
            commit_timeout: Timestamp::from_timestamp_millis(300),
            vote_timeout: Timestamp::from_timestamp_millis(400),
        };

        let vote_config_bytes = to_bytes(&vote_config);

        let mut ctx = InitContextTest::empty();
        ctx.set_parameter(&vote_config_bytes);
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(1));

        let result = setup(&ctx);
        let state = match result {
            Ok(s) => s,
            Err(e) => fail!("Setup failed: {:?}", e),
        };

        claim_eq!(
            state.config.deposit,
            Amount::from_micro_ccd(0),
            "Deposit should be 0"
        );
        claim_eq!(
            state.config.voting_question,
            "Vote for x".to_string(),
            "Voting question should be: Vote for x"
        );

        claim_eq!(
            state.voting_phase,
            VotingPhase::Registration,
            "VotingPhase should be Registration"
        );

        claim_eq!(
            state.voting_result,
            -1,
            "Voting result should be -1, since voting is not done"
        );

        claim!(
            state.voters.contains_key(&account1),
            "Map of voters should contain account1"
        );
        claim!(
            state.voters.contains_key(&account2),
            "Map of voters should contain account2"
        );

        let voter_default: Voter = Default::default();
        claim_eq!(
            state.voters.get(&account1),
            Some(&voter_default),
            "Vote object should be empty"
        );
        claim_eq!(
            state.voters.get(&account2),
            Some(&voter_default),
            "Vote object should be empty"
        );
    }

    #[concordium_test]
    fn test_register() {
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);

        let vote_config = VoteConfig {
            authorized_voters: vec![account1, account2],
            voting_question: "Vote for x".to_string(),
            deposit: Amount::from_micro_ccd(0),
            registration_timeout: Timestamp::from_timestamp_millis(100),
            precommit_timeout: Timestamp::from_timestamp_millis(200),
            commit_timeout: Timestamp::from_timestamp_millis(300),
            vote_timeout: Timestamp::from_timestamp_millis(400),
        };

        // Create pk, sk pair of g^x and x for account1
        let x = Scalar::<Secp256k1>::random();
        let g_x = Point::generator() * x.clone();

        let register_message = RegisterMessage {
            voting_key: g_x.to_bytes(true).to_vec(),
            voting_key_zkp: serde_json::to_vec(&crypto::create_dl_zkp(x)).unwrap(),
        };

        let register_message_bytes = to_bytes(&register_message);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_parameter(&register_message_bytes);
        ctx.set_sender(Address::Account(account1));
        ctx.set_self_balance(Amount::from_micro_ccd(0));
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(1));

        let mut voters = BTreeMap::new();
        voters.insert(account1, Default::default());
        voters.insert(account2, Default::default());

        let mut state = VotingState {
            config: vote_config,
            voting_phase: VotingPhase::Registration,
            voting_result: -1,
            voters,
        };

        let result: Result<ActionsTree, _> = register(&ctx, Amount::from_micro_ccd(0), &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        claim_eq!(
            actions,
            ActionsTree::Accept,
            "Contract produced wrong action"
        );
    }
}
