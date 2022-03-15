// Concordium smart contract std lib
use concordium_std::{collections::*,*};
use num_bigint::BigUint;
use sha2::{Sha256, Digest};

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

// TYPES:
#[derive(Serialize)]
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

#[derive(Serialize, Default)]
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
    b2: Vec<u8>
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

#[derive(Serialize, SchemaType, Default)]
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
    NegativeDeposit
}

// SETUP PHASE: function to create an instance of the contract with a voting config as parameter
#[init(contract = "open_vote_network", parameter = "VoteConfig")]
fn setup(ctx: &impl HasInitContext) -> Result<VotingState, SetupError> {
    let vote_config: VoteConfig = ctx.parameter_cursor().get()?;

    // Ensure config is valid
    ensure!(vote_config.registration_timeout > ctx.metadata().slot_time(), SetupError::InvalidRegistrationTimeout);
    ensure!(vote_config.precommit_timeout > vote_config.registration_timeout, SetupError::InvalidPrecommitTimeout);
    ensure!(vote_config.commit_timeout > vote_config.precommit_timeout, SetupError::InvalidCommitTimeout);
    ensure!(vote_config.vote_timeout > vote_config.commit_timeout, SetupError::InvalidVoteTimeout);
    ensure!(vote_config.deposit >= Amount::zero(), SetupError::NegativeDeposit);
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
    _ctx: &impl HasReceiveContext,
    _deposit: Amount,
    _state: &mut VotingState,
) -> ReceiveResult<A> {
    // check address of caller is an authorized voter, check deposit, check ZKP
    // add their voting key to state, "register them", Voter struct?
    todo!();
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
        todo!();
    }
}
