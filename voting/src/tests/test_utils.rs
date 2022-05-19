//! Rust file containing utility functions for unit tests.

use crate::{types::VotingPhase, VoteConfig, VotingState};
use concordium_std::*;
use test_infrastructure::*;

pub fn setup_test_config(
    number_of_accounts: i32,
    deposit: Amount,
) -> (Vec<AccountAddress>, VoteConfig) {
    let mut voters = Vec::new();
    for i in 0..number_of_accounts {
        voters.push(AccountAddress([i as u8; 32]))
    }

    let vote_config = VoteConfig {
        authorized_voters: voters.clone(),
        voting_question: "Vote for x".to_string(),
        deposit,
        registration_timeout: Timestamp::from_timestamp_millis(100),
        commit_timeout: Timestamp::from_timestamp_millis(200),
        vote_timeout: Timestamp::from_timestamp_millis(300),
    };

    (voters, vote_config)
}

pub fn setup_init_context(parameter: &Vec<u8>) -> TestInitContext {
    let mut ctx = TestInitContext::empty();
    ctx.set_parameter(parameter);
    ctx.metadata_mut()
        .set_slot_time(Timestamp::from_timestamp_millis(1));

    ctx
}

pub fn setup_receive_context(
    parameter: Option<&Vec<u8>>,
    sender: AccountAddress,
    state: VotingState<TestStateApi>,
    state_builder: TestStateBuilder,
) -> (TestReceiveContext, TestHost<VotingState<TestStateApi>>) {
    let mut ctx = TestReceiveContext::empty();
    let mut host = TestHost::new(state, state_builder);

    // Set parameter if it exists
    match parameter {
        Some(p) => {
            ctx.set_parameter(p);
            ()
        }
        None => (),
    };

    ctx.set_sender(Address::Account(sender));
    host.set_self_balance(Amount::from_micro_ccd(0));
    ctx.metadata_mut()
        .set_slot_time(Timestamp::from_timestamp_millis(1));

    (ctx, host)
}

pub fn setup_state(
    accounts: &Vec<AccountAddress>,
    vote_config: VoteConfig,
    phase: VotingPhase,
) -> (VotingState<TestStateApi>, TestStateBuilder) {
    let mut state_builder = TestStateBuilder::new();
    let mut voters = state_builder.new_map();

    // Add voters to starting state if we are not testing registration and instead one of the later phases with state
    if phase != VotingPhase::Registration {
        for account in accounts.into_iter() {
            voters.insert(*account, Default::default());
        }
    }

    let state = VotingState {
        config: vote_config,
        voting_phase: phase,
        voting_result: (-1, -1),
        voters,
    };

    (state, state_builder)
}
