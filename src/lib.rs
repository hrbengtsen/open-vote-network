// Concordium smart contract std lib
use concordium_std::{collections::*, *};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/* Crypto primitives examples for reference

- Currently no cryptographic primitives in concordium_std, so we make use of external crates for sha256 and 256-bit ints. These are not serializable, but can be converted to and from byte vectors: Vec<u8>

HASHING:
// create a Sha256 object
let mut hasher = Sha256::new();

// write input message that needs to be hashed
hasher.update(b"hello world");

// read hash digest and consume hasher (hash input)
let result = hasher.finalize();

// turn result of generic u8 array into Vec<u8>
let result_as_vec = result.as_slice().to_vec();

// how to assign above to property in voter struct
let voter = Voter {
    voting_key: result_as_vec,
};

BIGUINT:
// example conversions with biguint
let voting_key_as_biguint: BigUint = BigUint::from_bytes_be(&voter.voting_key);
let voting_key_back_to_vec = voting_key_as_biguint.to_bytes_be();

*/

// CONSTANTS:
const p: BigUint = BigUint::from_bytes_be(b"122107680324163731326195628876962217227875875104674957513153575181502134281591731264736894697896448600303841599180007822537155380562690656525291030336915557804704973775064507249831637820895851942068309715506100839290477208669512224410638746767879467597674173984949323476753244557316208119431089138718949132351");
const q: BigUint = BigUint::from_bytes_be(b"1036046097373825395468779246836445261226811567691");
const g: BigUint = BigUint::from_bytes_be(b"116394054093307450289544888337202347849872056659441871688204156656310478093839952009536842785765550012028719323064129318651856685904446304811611259691682858564041021445027520167922966252711476429426681586559668125838537840789547388645907972372948843324349051067516211395666832500872531469227007758406595295035");

// TYPES:
#[derive(Serialize, PartialEq)]
enum VotingPhase {
    Registration,
    Precommit,
    Commit,
    Vote,
    Result,
}

type RegistrationTimeout = Timestamp;
type PrecommitTimeout = Timestamp;
type CommitTimeout = Timestamp;
type VoteTimeout = Timestamp;

#[derive(Serialize, SchemaType)]
struct VoteConfig {
    authorized_voters: Vec<AccountAddress>,
    voting_question: String,
    deposit: Amount,
    registration_timeout: RegistrationTimeout,
    precommit_timeout: PrecommitTimeout,
    commit_timeout: CommitTimeout,
    vote_timeout: VoteTimeout,
}

type VotingKeyZKP = (Vec<u8>, Vec<u8>);

#[derive(Serialize, SchemaType)]
struct RegisterMessage {
    voting_key: Vec<u8>,
    voting_key_zkp: VotingKeyZKP,
}

type ReconstructedKey = Vec<u8>;

type Commitment = Vec<u8>;

#[derive(Serialize, Default, PartialEq)]
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
    vote: Vec<u8>,
    vote_zkp: OneInTwoZKP,
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

#[derive(Serialize, SchemaType, Default, PartialEq)]
struct Voter {
    voting_key: Vec<u8>,
    voting_key_zkp: VotingKeyZKP,
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
    // Deposit does not equal the requried amount
    DepositNotEnough,
    // Not in registration phase
    NotRegistrationPhase,
    // Registration phase has ended
    PhaseEnded,
    // Voter not found
    VoterNotFound,
    // Voter is already registered
    AlreadyRegistered,
}

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
    // check address of caller is an authorized voter, check deposit, check ZKP
    // add their voting key to state, "register them", Voter struct?
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
        RegisterError::DepositNotEnough
    );
    ensure!(
        ctx.metadata().slot_time() <= state.config.registration_timeout,
        RegisterError::PhaseEnded
    );

    // Ensure voters only register once
    let voter = match state.voters.get(&sender_address) {
        Some(v) => v,
        None => bail!(RegisterError::VoterNotFound),
    };
    ensure!(
        voter.voting_key == Vec::new(),
        RegisterError::AlreadyRegistered
    );

    // Check the ZKP of the sender
    let mut hasher = Sha256::new();

    let g_bytes = BigUint::to_bytes_be(&g);

    // Combine: g, g^x_i, g^w
    let hash_message = [
        g_bytes,
        register_message.voting_key,
        register_message.voting_key_zkp.0,
    ]
    .concat();
    hasher.update(hash_message);

    // Construct math variables
    let z = hasher.finalize().as_slice().to_vec();
    let r = BigUint::from_bytes_be(&register_message.voting_key_zkp.1);
    let g_r = g.pow(r.try_into().expect("Exponent too large"));
    let g_x = BigUint::from_bytes_be(&register_message.voting_key);
    let g_x_z = g_x
        .pow(
            BigUint::from_bytes_be(&z)
                .try_into()
                .expect("Exponent too large"),
        )
        .to_bytes_be();

    // Check validity of ZKP
    ensure!(register_message.voting_key_zkp.0 == g_x_z);

    // Add register message to correct voter (i.e. voting key and zkp)
    voter.voting_key = register_message.voting_key;
    voter.voting_key_zkp = register_message.voting_key_zkp;

    // Check if all eligible voters has registered
    if state
        .voters
        .into_iter()
        .all(|(_, v)| v.voting_key != Vec::new())
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
            Err(_) => fail!("Setup failed"),
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
}
