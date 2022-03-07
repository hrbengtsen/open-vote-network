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

// Contract state
#[contract_state(contract = "open_vote_network")]
#[derive(Serialize, SchemaType)]
pub struct VotingState {
    config: VoteConfig,
    voting_phase: VotingPhase,
    // more relevant state: voting keys, zkps?
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

// PRECOMMIT PHASE:
#[receive(contract = "open_vote_network", name = "submit", parameter = "ReconstructedKey")]
fn submit_reconstructed_key<A: HasActions>(_ctx: &impl HasReceiveContext, _state: &mut VotingState) -> ReceiveResult<A> {
    todo!();
}

// COMMIT PHASE:
fn commit() {
    todo!();
}

// VOTE PHASE:
fn vote() {
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