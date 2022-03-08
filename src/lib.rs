// Concordium smart contract std lib
use concordium_std::*;

// TYPES:
#[derive(Serialize)]
enum VotingPhase {
    Setup,
    Registration,
    Precommit,
    Commit,
    Vote,
    Result
}

type RegistrationTimeout = Duration;
type PrecommitTimeout = Duration;
type CommitTimeout = Duration;
type VoteTimeout = Duration;

#[derive(Serialize, SchemaType)]
struct VoteConfig {
    authorized_voters: Vec<AccountAddress>,
    voting_question: String,
    deposit: Amount,
    registration_timeout: RegistrationTimeout,
    precommit_timeout: PrecommitTimeout,
    commit_timeout: CommitTimeout,
    vote_timeout: VoteTimeout
}

#[derive(Serialize, SchemaType)]
struct RegisterMessage {
    voting_key: todo!(), // is large number g^xi, find crypto crate to use for types? bigint?
    voting_key_zkp: todo!()
}

type ReconstructedKey = todo!();

type Commitment = todo!();

#[derive(Serialize, SchemaType)]
struct VoteMessage {
    vote: todo!(),
    vote_zkp: todo!()
}

// Contract state
#[contract_state(contract = "open_vote_network")]
#[derive(Serialize, SchemaType)]
pub struct VotingState {
    config: VoteConfig,
    voting_phase: VotingPhase,
    voting_result: todo!(),
    voters: HashMap<AccountAddress, Voter> // do we need different map (TreeMap?) to have some order?
}

#[derive(Serialize, SchemaType)]
struct Voter {
    voting_key: todo!(),
    voting_key_zkp: todo!(),
    reconstructed_key: todo!(),
    commitment: todo!(),
    vote: todo!(),
    vote_zkp: todo!()
}

// SETUP PHASE: function to create an instance of the contract with a voting config as parameter
#[init(contract = "open_vote_network", parameter = "VoteConfig")]
fn setup(_ctx: &impl HasInitContext) -> InitResult<VotingState> {
    // apply voting config, change voting phase and start relevant timer
    todo!();
}

// REGISTRATION PHASE: function voters call to register them for the vote by sending (voting key, ZKP, deposit)
#[receive(contract = "open_vote_network", name = "register", parameter = "RegisterMessage", payable)]
fn register<A: HasActions>(_ctx: &impl HasReceiveContext, _deposit: Amount, _state: &mut VotingState) -> ReceiveResult<A> {
    // check address of caller is an authorized voter, check deposit, check ZKP
    // add their voting key to state, "register them", Voter struct?
    todo!();
}

// PRECOMMIT PHASE: function voters call to send reconstructed key
#[receive(contract = "open_vote_network", name = "submit", parameter = "ReconstructedKey")]
fn submit_reconstructed_key<A: HasActions>(_ctx: &impl HasReceiveContext, _state: &mut VotingState) -> ReceiveResult<A> {
    // handle timeout, save voters reconstructed key in voter state
    todo!();
}

// COMMIT PHASE: function voters call to commit to their vote (by sending a hash of it)
#[receive(contract = "open_vote_network", name = "commit", parameter = "Commitment")]
fn commit<A: HasActions>(_ctx: &impl HasReceiveContext, _state: &mut VotingState) -> ReceiveResult<A> {
    todo!();
}

// VOTE PHASE: function voters call to send they encrypted vote along with a one-out-of-two ZKP
#[receive(contract = "open_vote_network", name = "vote", parameter = "VoteMessage")]
fn vote<A: HasActions>(_ctx: &impl HasReceiveContext, _state: &mut VotingState) -> ReceiveResult<A> {
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