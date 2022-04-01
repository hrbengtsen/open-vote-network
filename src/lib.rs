use concordium_std::{collections::*, *};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Point, Secp256k1};
use sha2::Sha256;

mod crypto;
mod types;

/// Contract enum and structs

// REMEBER TO CHECK FOR ABORT CASE IN ALL FUNCTIONS
#[derive(Serialize, PartialEq)]
enum VotingPhase {
    Registration,
    Precommit,
    Commit,
    Vote,
    Result,
    Abort,
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
    voting_phase: VotingPhase,
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
    InvalidVotingKey,
}

#[derive(Debug, PartialEq, Eq, Reject)]
enum PrecommitError {
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
enum CommitError {
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
enum VoteError {
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
}

#[derive(Debug, PartialEq, Eq, Reject)]
enum ResultError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Sender cannot be contract
    ContractSender,
    // Not in result phase
    NotResultPhase,
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
    ensure!(state.config.deposit == deposit, RegisterError::WrongDeposit);
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
        Err(_) => bail!(RegisterError::InvalidVotingKey),
    };
    match point.ensure_nonzero() {
        Ok(_) => (),
        Err(_) => bail!(RegisterError::InvalidVotingKey),
    }

    // Check validity of ZKP
    let decoded_proof: DLogProof<Secp256k1, Sha256> =
        serde_json::from_slice(&register_message.voting_key_zkp).unwrap();
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
    name = "precommit",
    parameter = "ReconstructedKey"
)]
fn precommit<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, PrecommitError> {
    let reconstructed_key: ReconstructedKey = ctx.parameter_cursor().get()?;

    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(PrecommitError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == VotingPhase::Precommit,
        PrecommitError::NotPrecommitPhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        PrecommitError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.precommit_timeout,
        PrecommitError::PhaseEnded
    );

    // Save voters reconstructed key in voter state
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(PrecommitError::VoterNotFound),
    };
    voter.reconstructed_key = reconstructed_key.0;

    // Check if all voters have submitted their reconstructed key
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.reconstructed_key != Vec::<u8>::new())
    {
        state.voting_phase = VotingPhase::Commit;
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
) -> Result<A, CommitError> {
    let commitment: Commitment = ctx.parameter_cursor().get()?;

    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(CommitError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == VotingPhase::Commit,
        CommitError::NotCommitPhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        CommitError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.commit_timeout,
        CommitError::PhaseEnded
    );

    // Save voters commitment in voter state
    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(CommitError::VoterNotFound),
    };
    voter.commitment = commitment.0;

    // Check if all voters have committed to their vote
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.commitment != Vec::<u8>::new())
    {
        state.voting_phase = VotingPhase::Vote;
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
) -> Result<A, VoteError> {
    let vote_message: VoteMessage = ctx.parameter_cursor().get()?;

    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(VoteError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(
        state.voting_phase == VotingPhase::Vote,
        VoteError::NotVotePhase
    );
    ensure!(
        state.voters.contains_key(&sender_address),
        VoteError::UnauthorizedVoter
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.vote_timeout,
        VoteError::PhaseEnded
    );

    let voter = match state.voters.get_mut(&sender_address) {
        Some(v) => v,
        None => bail!(VoteError::VoterNotFound),
    };
    ensure!(
        crypto::verify_one_out_of_two_zkp(
            vote_message.vote_zkp.clone(),
            Point::<Secp256k1>::from_bytes(&voter.reconstructed_key).unwrap()
        ),
        VoteError::InvalidZKP
    );

    ensure!(
        crypto::check_commitment(
            Point::<Secp256k1>::from_bytes(&vote_message.vote).unwrap(),
            voter.commitment.clone()
        ),
        VoteError::VoteCommitmentMismatch
    );

    voter.vote = vote_message.vote;
    voter.vote_zkp = vote_message.vote_zkp;

    // Check all voters have voted
    if state
        .voters
        .clone()
        .into_iter()
        .all(|(_, v)| v.vote != Vec::<u8>::new())
    {
        state.voting_phase = VotingPhase::Result;
    }

    // TODO: need to to refund sender address deposit

    Ok(A::accept())
}

// RESULT PHASE:
#[receive(contract = "open_vote_network", name = "result")]
fn result<A: HasActions>(
    _ctx: &impl HasReceiveContext,
    state: &mut VotingState,
) -> Result<A, ResultError> {
    ensure!(
        state.voting_phase == VotingPhase::Result,
        ResultError::NotResultPhase
    );
    let mut votes = Vec::new();
    for (_, v) in state.voters.clone().into_iter() {
        votes.push(Point::<Secp256k1>::from_bytes(&v.vote).unwrap());
    }

    let yes_votes = crypto::brute_force_tally(votes.clone());
    let no_votes = i32::try_from(votes.len()).unwrap() - yes_votes;

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
        VotingPhase::Registration => {
            if now > state.config.registration_timeout {
                state.voting_phase = VotingPhase::Precommit
            }
        }
        VotingPhase::Precommit => {
            if state
                .voters
                .clone()
                .into_iter()
                .all(|(_, v)| v.reconstructed_key != Vec::<u8>::new())
            {
                state.voting_phase = VotingPhase::Commit
            } else if now > state.config.precommit_timeout {
                state.voting_phase = VotingPhase::Abort
            }
        }
        VotingPhase::Commit => {
            if state
                .voters
                .clone()
                .into_iter()
                .all(|(_, v)| v.commitment != Vec::<u8>::new())
            {
                state.voting_phase = VotingPhase::Vote
            } else if now > state.config.commit_timeout {
                state.voting_phase = VotingPhase::Abort
            }
        }
        VotingPhase::Vote => {
            if state
                .voters
                .clone()
                .into_iter()
                .all(|(_, v)| v.vote != Vec::<u8>::new())
            {
                state.voting_phase = VotingPhase::Result
            } else if now > state.config.vote_timeout {
                state.voting_phase = VotingPhase::Abort
            }
        }
        _ => (), // Handles abort and result phases which we cant move on from
    };
    Ok(A::accept())
}

// UNIT TESTS:
#[concordium_cfg_test]
mod tests {
    use super::*;
    use curv::elliptic::curves::Scalar;
    use test_infrastructure::*;

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
            (-1, -1),
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
        let (x, g_x) = crypto::create_votingkey_pair();

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
            voting_result: (-1, -1),
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

        let voter1 = match state.voters.get(&account1) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(
            voter1.voting_key,
            Vec::<u8>::new(),
            "Voter 1 should have a registered voting key"
        );
        claim_ne!(
            voter1.voting_key_zkp,
            Vec::<u8>::new(),
            "Voter 1 should have a registered voting key zkp"
        );
    }

    #[concordium_test]
    fn test_change_phase() {
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

        let mut ctx = ReceiveContextTest::empty();
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
            voting_result: (-1, -1),
            voters,
        };

        let result: Result<ActionsTree, _> = change_phase(&ctx, &mut state);
        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };
        claim_eq!(
            actions,
            ActionsTree::Accept,
            "Contract produced wrong action"
        );

        // Testing that the phase does not change when time has not passed registration timeout
        claim_eq!(
            state.voting_phase,
            VotingPhase::Registration,
            "Did change phase but should not have as time is not beyond registration timeout"
        );

        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(101));

        let result: Result<ActionsTree, _> = change_phase(&ctx, &mut state);
        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };
        claim_eq!(
            actions,
            ActionsTree::Accept,
            "Contract produced wrong action"
        );

        // Testing that the phase changes when the timeout has passed
        claim_eq!(
            state.voting_phase,
            VotingPhase::Precommit,
            "Did not change from registration to precommit"
        )

        // More exhaustive tests needed
    }

    #[concordium_test]
    fn test_precommit() {
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let account3 = AccountAddress([3u8; 32]);

        let vote_config = VoteConfig {
            authorized_voters: vec![account1, account2, account3],
            voting_question: "Vote for x".to_string(),
            deposit: Amount::from_micro_ccd(0),
            registration_timeout: Timestamp::from_timestamp_millis(100),
            precommit_timeout: Timestamp::from_timestamp_millis(200),
            commit_timeout: Timestamp::from_timestamp_millis(300),
            vote_timeout: Timestamp::from_timestamp_millis(400),
        };

        // Create pk, sk pair of g^x and x for accounts
        let (_x1, g_x1) = crypto::create_votingkey_pair();
        let (_x2, g_x2) = crypto::create_votingkey_pair();
        let (_x3, g_x3) = crypto::create_votingkey_pair();

        // Compute reconstructed key
        let g_y1 = crypto::compute_reconstructed_key(
            vec![g_x1.clone(), g_x2.clone(), g_x3.clone()],
            g_x1.clone(),
        );
        let g_y2 = crypto::compute_reconstructed_key(
            vec![g_x1.clone(), g_x2.clone(), g_x3.clone()],
            g_x2.clone(),
        );
        let g_y3 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone(), g_x3.clone()], g_x3);

        // Convert to the struct that is sent as parameter to precommit function
        let reconstructed_key = ReconstructedKey(g_y1.to_bytes(true).to_vec());
        let reconstructed_key_bytes = to_bytes(&reconstructed_key);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_parameter(&reconstructed_key_bytes);
        ctx.set_sender(Address::Account(account1));
        ctx.set_self_balance(Amount::from_micro_ccd(0));
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(1));

        let mut voters = BTreeMap::new();
        voters.insert(account1, Default::default());
        voters.insert(account2, Default::default());
        voters.insert(account3, Default::default());

        let mut state = VotingState {
            config: vote_config,
            voting_phase: VotingPhase::Precommit,
            voting_result: (-1, -1),
            voters,
        };

        let result: Result<ActionsTree, _> = precommit(&ctx, &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        claim_eq!(
            actions,
            ActionsTree::Accept,
            "Contract produced wrong action"
        );

        let voter1 = match state.voters.get(&account1) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(
            voter1.reconstructed_key,
            Vec::<u8>::new(),
            "Voter 1 should have a registered reconstructed key"
        );

        // Test function briefly for other 2 accounts
        let reconstructed_key = ReconstructedKey(g_y2.to_bytes(true).to_vec());
        let reconstructed_key_bytes = to_bytes(&reconstructed_key);

        ctx.set_parameter(&reconstructed_key_bytes);
        ctx.set_sender(Address::Account(account2));

        let result: Result<ActionsTree, _> = precommit(&ctx, &mut state);

        let _ = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        let reconstructed_key = ReconstructedKey(g_y3.to_bytes(true).to_vec());
        let reconstructed_key_bytes = to_bytes(&reconstructed_key);

        ctx.set_parameter(&reconstructed_key_bytes);
        ctx.set_sender(Address::Account(account3));

        let result: Result<ActionsTree, _> = precommit(&ctx, &mut state);

        let _ = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };
    }

    #[concordium_test]
    fn test_commit() {
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

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = crypto::create_votingkey_pair();
        let (_x2, g_x2) = crypto::create_votingkey_pair();

        // Compute reconstructed key
        let g_y1 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x1.clone());
        let g_y2 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x2.clone());

        // Convert to the struct that is sent as parameter to precommit function

        let g_v = Point::generator().to_point();
        let commitment = Commitment(crypto::commit_to_vote(x1, g_y1, g_v));
        let commitment_bytes = to_bytes(&commitment);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_parameter(&commitment_bytes);
        ctx.set_sender(Address::Account(account1));
        ctx.set_self_balance(Amount::from_micro_ccd(0));
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(1));

        let mut voters = BTreeMap::new();
        voters.insert(account1, Default::default());
        voters.insert(account2, Default::default());

        let mut state = VotingState {
            config: vote_config,
            voting_phase: VotingPhase::Commit,
            voting_result: (-1, -1),
            voters,
        };

        let result: Result<ActionsTree, _> = commit(&ctx, &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        claim_eq!(
            actions,
            ActionsTree::Accept,
            "Contract produced wrong action"
        );

        let voter1 = match state.voters.get(&account1) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(
            voter1.commitment,
            Vec::<u8>::new(),
            "Voter 1 should have a committed to a vote"
        );
    }
    #[concordium_test]
    fn test_vote() {
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

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = crypto::create_votingkey_pair();
        let (x2, g_x2) = crypto::create_votingkey_pair();

        // Compute reconstructed key
        let g_y1 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x1.clone());
        let g_y2 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x2.clone());

        // Testing no vote
        let one_two_zkp_account1 =
            crypto::create_one_out_of_two_zkp_no(g_x1, g_y1.clone(), x1.clone());
        let vote_message1 = VoteMessage {
            vote: ((g_y1.clone() * x1.clone()) + Point::<Secp256k1>::zero())
                .to_bytes(true)
                .to_vec(),
            vote_zkp: one_two_zkp_account1,
        };
        let vote_message_bytes = to_bytes(&vote_message1);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_parameter(&vote_message_bytes);
        ctx.set_sender(Address::Account(account1));
        ctx.set_self_balance(Amount::from_micro_ccd(0));
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(1));

        let mut voters = BTreeMap::new();
        voters.insert(
            account1,
            Voter {
                reconstructed_key: g_y1.to_bytes(true).to_vec(),
                commitment: crypto::commit_to_vote(x1, g_y1, Point::<Secp256k1>::zero()),
                ..Default::default()
            },
        );
        voters.insert(
            account2,
            Voter {
                reconstructed_key: g_y2.to_bytes(true).to_vec(),
                commitment: crypto::commit_to_vote(
                    x2.clone(),
                    g_y2.clone(),
                    Point::generator().to_point(),
                ),
                ..Default::default()
            },
        );

        let mut state = VotingState {
            config: vote_config,
            voting_phase: VotingPhase::Vote,
            voting_result: (-1, -1),
            voters,
        };

        let result: Result<ActionsTree, _> = vote(&ctx, &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        claim_eq!(
            actions,
            ActionsTree::Accept,
            "Contract produced wrong action"
        );

        let voter1 = match state.voters.get(&account1) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(voter1.vote, Vec::<u8>::new(), "Voter 1 should have voted");

        // Testing yes vote
        let one_two_zkp_account2 =
            crypto::create_one_out_of_two_zkp_yes(g_x2, g_y2.clone(), x2.clone());
        let vote_message2 = VoteMessage {
            vote: ((g_y2 * x2) + Point::generator()).to_bytes(true).to_vec(),
            vote_zkp: one_two_zkp_account2,
        };
        let vote_message_bytes = to_bytes(&vote_message2);
        ctx.set_parameter(&vote_message_bytes);
        ctx.set_sender(Address::Account(account2));

        let result: Result<ActionsTree, _> = vote(&ctx, &mut state);

        let _ = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };
    }
}
