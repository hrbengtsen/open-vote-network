use crate::*;
pub mod test_utils;
use group::GroupEncoding;

// UNIT TESTS:
#[concordium_cfg_test]
mod tests {
    use super::*;
    use test_infrastructure::*;

    #[concordium_test]
    fn test_setup() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        let vote_config_bytes = to_bytes(&vote_config);

        let ctx = test_utils::setup_init_context(&vote_config_bytes);

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
            types::VotingPhase::Registration,
            "types::VotingPhase should be Registration"
        );

        claim_eq!(
            state.voting_result,
            (-1, -1),
            "Voting result should be -1, since voting is not done"
        );

        claim!(
            state.voters.contains_key(&accounts[0]),
            "Map of voters should contain account1"
        );
        claim!(
            state.voters.contains_key(&accounts[1]),
            "Map of voters should contain account2"
        );
        claim!(
            state.voters.contains_key(&accounts[2]),
            "Map of voters should contain account3"
        );

        let voter_default: Voter = Default::default();
        claim_eq!(
            state.voters.get(&accounts[0]),
            Some(&voter_default),
            "Vote object should be empty"
        );
        claim_eq!(
            state.voters.get(&accounts[1]),
            Some(&voter_default),
            "Vote object should be empty"
        );
        claim_eq!(
            state.voters.get(&accounts[2]),
            Some(&voter_default),
            "Vote object should be empty"
        );
    }

    #[concordium_test]
    fn test_register() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        // Create pk, sk pair of g^x and x for account1
        let (x, g_x) = crypto::create_votingkey_pair(1);

        let register_message = RegisterMessage {
            voting_key: g_x.to_bytes().to_vec(),
            voting_key_zkp: crypto::create_dl_zkp(g_x, x),
        };

        let register_message_bytes = to_bytes(&register_message);

        let ctx = test_utils::setup_receive_context(Some(&register_message_bytes), accounts[0]);

        let mut state = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Registration);

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

        let voter1 = match state.voters.get(&accounts[0]) {
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
            Default::default(),
            "Voter 1 should have a registered voting key zkp"
        );
    }

    #[concordium_test]
    fn test_change_phase() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        let mut ctx = test_utils::setup_receive_context(None, accounts[0]);

        let mut state = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Registration);

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
            types::VotingPhase::Registration,
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
            types::VotingPhase::Precommit,
            "Did not change from registration to precommit"
        );

        // More exhaustive tests needed
    }

    #[concordium_test]
    fn test_precommit() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        // Create pk, sk pair of g^x and x for accounts
        let (_x1, g_x1) = crypto::create_votingkey_pair(1);
        let (_x2, g_x2) = crypto::create_votingkey_pair(2);
        let (_x3, g_x3) = crypto::create_votingkey_pair(3);

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
        let reconstructed_key = ReconstructedKey(g_y1.to_bytes().to_vec());
        let reconstructed_key_bytes = to_bytes(&reconstructed_key);

        let mut ctx = test_utils::setup_receive_context(Some(&reconstructed_key_bytes), accounts[0]);

        let mut state = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Precommit);

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

        let voter1 = match state.voters.get(&accounts[0]) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(
            voter1.reconstructed_key,
            Vec::<u8>::new(),
            "Voter 1 should have a registered reconstructed key"
        );

        // Test function briefly for other 2 accounts
        let reconstructed_key = ReconstructedKey(g_y2.to_bytes().to_vec());
        let reconstructed_key_bytes = to_bytes(&reconstructed_key);

        ctx.set_parameter(&reconstructed_key_bytes);
        ctx.set_sender(Address::Account(accounts[1]));

        let result: Result<ActionsTree, _> = precommit(&ctx, &mut state);

        let _ = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        let reconstructed_key = ReconstructedKey(g_y3.to_bytes().to_vec());
        let reconstructed_key_bytes = to_bytes(&reconstructed_key);

        ctx.set_parameter(&reconstructed_key_bytes);
        ctx.set_sender(Address::Account(accounts[2]));

        let result: Result<ActionsTree, _> = precommit(&ctx, &mut state);

        let _ = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };
    }

    #[concordium_test]
    fn test_commit() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = crypto::create_votingkey_pair(1);
        let (_x2, g_x2) = crypto::create_votingkey_pair(2);

        // Compute reconstructed key
        let g_y1 = crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x1.clone());
        //let g_y2 = crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x2.clone());

        // Convert to the struct that is sent as parameter to precommit function
        let g_v = ProjectivePoint::GENERATOR;
        let commitment = Commitment(crypto::commit_to_vote(&x1, &g_y1, g_v));
        let commitment_bytes = to_bytes(&commitment);

        let ctx = test_utils::setup_receive_context(Some(&commitment_bytes), accounts[0]);

        let mut state = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Commit);

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

        let voter1 = match state.voters.get(&accounts[0]) {
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
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(1));

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = crypto::create_votingkey_pair(1);
        let (x2, g_x2) = crypto::create_votingkey_pair(2);

        // Compute reconstructed key
        let g_y1 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x1.clone());
        let g_y2 =
            crypto::compute_reconstructed_key(vec![g_x1.clone(), g_x2.clone()], g_x2.clone());

        // Testing no vote
        let one_two_zkp_account1 =
            crypto::create_one_out_of_two_zkp_no(g_x1, g_y1.clone(), x1.clone());
        let vote_message1 = VoteMessage {
            vote: ((g_y1.clone() * x1.clone()) + ProjectivePoint::IDENTITY)
                .to_bytes()
                .to_vec(),
            vote_zkp: one_two_zkp_account1,
        };
        let vote_message_bytes = to_bytes(&vote_message1);

        let mut ctx = test_utils::setup_receive_context(Some(&vote_message_bytes), accounts[0]);

        let mut voters = BTreeMap::new();
        voters.insert(
            accounts[0],
            Voter {
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: crypto::commit_to_vote(&x1, &g_y1, ProjectivePoint::IDENTITY),
                ..Default::default()
            },
        );
        voters.insert(
            accounts[1],
            Voter {
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: crypto::commit_to_vote(
                    &x2,
                    &g_y2,
                    ProjectivePoint::GENERATOR,
                ),
                ..Default::default()
            },
        );

        let mut state = VotingState {
            config: vote_config,
            voting_phase: types::VotingPhase::Vote,
            voting_result: (-1, -1),
            voters,
        };

        let result: Result<ActionsTree, _> = vote(&ctx, &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        // Check that account1 gets refund
        claim_eq!(
            actions,
            ActionsTree::simple_transfer(&accounts[0], Amount::from_micro_ccd(1)),
            "Contract produced wrong action"
        );

        let voter1 = match state.voters.get(&accounts[0]) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(voter1.vote, Vec::<u8>::new(), "Voter 1 should have voted");

        // Testing yes vote
        let one_two_zkp_account2 =
            crypto::create_one_out_of_two_zkp_yes(g_x2, g_y2.clone(), x2.clone());
        let vote_message2 = VoteMessage {
            vote: ((g_y2 * x2) + ProjectivePoint::GENERATOR).to_bytes().to_vec(),
            vote_zkp: one_two_zkp_account2,
        };
        let vote_message_bytes = to_bytes(&vote_message2);
        ctx.set_parameter(&vote_message_bytes);
        ctx.set_sender(Address::Account(accounts[1]));

        let result: Result<ActionsTree, _> = vote(&ctx, &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        // Check that account2 gets refund
        claim_eq!(
            actions,
            ActionsTree::simple_transfer(&accounts[1], Amount::from_micro_ccd(1)),
            "Contract produced wrong action"
        );
    }

    #[concordium_test]
    fn test_result() {
        let (accounts, vote_config) = test_utils::setup_test_config(4, Amount::from_micro_ccd(1));

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = crypto::create_votingkey_pair(1);
        let (x2, g_x2) = crypto::create_votingkey_pair(2);
        let (x3, g_x3) = crypto::create_votingkey_pair(3);
        let (x4, g_x4) = crypto::create_votingkey_pair(4);

        let list_of_voting_keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone(), g_x4.clone()];
        // Compute reconstructed key
        let g_y1 = crypto::compute_reconstructed_key(list_of_voting_keys.clone(), g_x1.clone());
        let g_y2 = crypto::compute_reconstructed_key(list_of_voting_keys.clone(), g_x2.clone());
        let g_y3 = crypto::compute_reconstructed_key(list_of_voting_keys.clone(), g_x3.clone());
        let g_y4 = crypto::compute_reconstructed_key(list_of_voting_keys, g_x4.clone());

        let ctx = test_utils::setup_receive_context(None, accounts[0]);

        let mut voters = BTreeMap::new();
        voters.insert(
            accounts[0],
            Voter {
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: crypto::commit_to_vote(
                    &x1,
                    &g_y1,
                    ProjectivePoint::IDENTITY,
                ),
                vote: ((g_y1.clone() * x1.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        voters.insert(
            accounts[1],
            Voter {
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: crypto::commit_to_vote(
                    &x2,
                    &g_y2,
                    ProjectivePoint::IDENTITY,
                ),
                vote: ((g_y2.clone() * x2.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        voters.insert(
            accounts[2],
            Voter {
                reconstructed_key: g_y3.to_bytes().to_vec(),
                commitment: crypto::commit_to_vote(
                    &x3,
                    &g_y3,
                    ProjectivePoint::GENERATOR,
                ),
                vote: ((g_y3.clone() * x3.clone()) + ProjectivePoint::GENERATOR)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        voters.insert(
            accounts[3],
            Voter {
                reconstructed_key: g_y4.to_bytes().to_vec(),
                commitment: crypto::commit_to_vote(
                    &x4,
                    &g_y4,
                    ProjectivePoint::GENERATOR,
                ),
                vote: ((g_y4.clone() * x4.clone()) + ProjectivePoint::GENERATOR)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );

        let mut state = VotingState {
            config: vote_config,
            voting_phase: types::VotingPhase::Result,
            voting_result: (-1, -1),
            voters,
        };

        let result: Result<ActionsTree, _> = result(&ctx, &mut state);

        let actions = match result {
            Err(e) => fail!("Contract recieve failed, but should not have: {:?}", e),
            Ok(actions) => actions,
        };

        claim_eq!(
            actions,
            ActionsTree::accept(),
            "Contract produced wrong action"
        );

        claim_eq!((2, 2), state.voting_result, "Wrong voting result")
    }
}
