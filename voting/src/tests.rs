//! Rust file containing the unit tests for the *voting* contract.

use crate::*;
pub mod test_utils;

#[concordium_cfg_test]
mod tests {
    use super::*;
    use group::GroupEncoding;
    use k256::ProjectivePoint;
    use test_infrastructure::*;

    #[concordium_test]
    fn test_setup() {
        let (_, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        let vote_config_bytes = to_bytes(&vote_config);
        let ctx = test_utils::setup_init_context(&vote_config_bytes);

        // Setup the state of the contract
        let (state, mut state_builder) =
            test_utils::setup_state(&Vec::<AccountAddress>::new(), vote_config, types::VotingPhase::Registration);

        let result = setup(&ctx, &mut state_builder);
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

        claim_eq!(
            state.voters.iter().count(),
            0,
            "Registered voters map should be empty"
        );
    }

    #[concordium_test]
    fn test_register() {
        //only create 1 eligble voter
        let (accounts, vote_config) = test_utils::setup_test_config(2, Amount::from_micro_ccd(0));

        // Setup the state of the contract
        let (state, state_builder) =
            test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Registration);

        // Create pk, sk pair of g^x and x for account1
        let (x, g_x) = off_chain::create_votingkey_pair();

        let register_message = RegisterMessage {
            voting_key: g_x.to_bytes().to_vec(),
            voting_key_zkp: off_chain::create_schnorr_zkp(g_x, x),
        };

        let register_message_bytes = to_bytes(&register_message);

        let (ctx, mut host) = test_utils::setup_receive_context(
            Some(&register_message_bytes),
            accounts[0],
            state,
            state_builder,
        );

        let result = register(&ctx, &mut host, Amount::from_micro_ccd(0));

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        let voter1 = match host.state().voters.get(&accounts[0]) {
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

        // Test for unauthorized voter
        let voter2 = AccountAddress([10 as u8; 32]);

        // Create pk, sk pair of g^x and x for account2
        let (x2, g_x2) = off_chain::create_votingkey_pair();

        let register_message2 = RegisterMessage {
            voting_key: g_x2.to_bytes().to_vec(),
            voting_key_zkp: off_chain::create_schnorr_zkp(g_x2, x2),
        };

        let register_message_bytes2 = to_bytes(&register_message2);

        // let (ctx, host) = test_utils::setup_receive_context(
        //     Some(&register_message_bytes2),
        //     voter2,
        //     state,
        //     state_builder,
        // );

        // let result = register(&ctx, &mut host, Amount::from_micro_ccd(0));

        // // Voter 2
        // claim_eq!(
        //     result,
        //     Err(types::RegisterError::UnauthorizedVoter),
        //     "Voter should be unauthorized"
        // );

        // //length of registred voters should still be only 1
        // claim_eq!(
        //     host.state().voters.iter().count(),
        //     1,
        //     "Length of voter should be 1"
        // );
    }

    #[concordium_test]
    fn test_change_phase() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(1));

        let (state, statte_builder) =
            test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Registration);

        let (mut ctx, mut host) =
            test_utils::setup_receive_context(None, accounts[0], state, statte_builder);

        // Simulate that the 3 voters have registered
        let (x1, g_x1) = off_chain::create_votingkey_pair();
        let (x2, g_x2) = off_chain::create_votingkey_pair();
        let (x3, g_x3) = off_chain::create_votingkey_pair();

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                voting_key: g_x1.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                voting_key: g_x2.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                voting_key: g_x2.to_bytes().to_vec(),
                ..Default::default()
            },
        );

        // Testing that the phase does not change when time has not passed registration timeout
        let result = change_phase(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract received failed, but should not have"
        );

        claim_eq!(
            host.state().voting_phase,
            types::VotingPhase::Registration,
            "Changed phase but should not have since time is not beyond registration timeout"
        );

        // Testing that the phase changes when the timeout has passed
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(101));

        let result = change_phase(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        claim_eq!(
            host.state().voting_phase,
            types::VotingPhase::Commit,
            "Did not change from registration to commit"
        );

        // Testing that the phase changes to abort phase if timer ran out and not all committed.
        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(201));

        let result = change_phase(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        claim_eq!(
            host.state().voting_phase,
            types::VotingPhase::Abort,
            "Should change to abort phase since no one comitted"
        );

        // Testing that phase changes from commit to vote, if all voters have reconstructed keys and commitments.
        host.state_mut().voting_phase = types::VotingPhase::Commit;

        let keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone()];

        let g_y1 = off_chain::compute_reconstructed_key(&keys, g_x1.clone());
        let g_y2 = off_chain::compute_reconstructed_key(&keys, g_x2.clone());
        let g_y3 = off_chain::compute_reconstructed_key(&keys, g_x3.clone());

        let g_v = ProjectivePoint::GENERATOR;
        let commitment1 = off_chain::commit_to_vote(&x1, &g_y1, g_v);
        let commitment2 = off_chain::commit_to_vote(&x2, &g_y2, g_v);
        let commitment3 = off_chain::commit_to_vote(&x3, &g_y3, g_v);

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: commitment1,
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: commitment2,
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                reconstructed_key: g_y3.to_bytes().to_vec(),
                commitment: commitment3,
                ..Default::default()
            },
        );

        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(201));

        let result = change_phase(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        claim_eq!(
            host.state().voting_phase,
            types::VotingPhase::Vote,
            "Should change to abort phase since no one comitted"
        );

        // Testing that phase changes from vote to result if all voted
        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                vote: g_v.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                vote: g_v.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                vote: g_v.to_bytes().to_vec(),
                ..Default::default()
            },
        );

        ctx.metadata_mut()
            .set_slot_time(Timestamp::from_timestamp_millis(301));

        let result = change_phase(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        claim_eq!(
            host.state().voting_phase,
            types::VotingPhase::Result,
            "Phase should have changed to result"
        )
    }

    #[concordium_test]
    fn test_commit() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(0));

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = off_chain::create_votingkey_pair();
        let (x2, g_x2) = off_chain::create_votingkey_pair();
        let (x3, g_x3) = off_chain::create_votingkey_pair();

        // Compute reconstructed key
        let keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone()];

        let g_y1 = off_chain::compute_reconstructed_key(&keys, g_x1.clone());
        let g_y2 = off_chain::compute_reconstructed_key(&keys, g_x2.clone());
        let g_y3 = off_chain::compute_reconstructed_key(&keys, g_x3);

        // Convert to the struct that is sent as parameter to precommit function
        let g_v = ProjectivePoint::GENERATOR;
        let commitment = off_chain::commit_to_vote(&x1, &g_y1, g_v);

        let commitment_message = CommitMessage {
            reconstructed_key: g_y1.to_bytes().to_vec(),
            commitment,
        };
        let commitment_message_bytes = to_bytes(&commitment_message);

        let (state, state_builder) =
            test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Commit);

        let (mut ctx, mut host) = test_utils::setup_receive_context(
            Some(&commitment_message_bytes),
            accounts[0],
            state,
            state_builder,
        );

        let result = commit(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        let voter1 = match host.state().voters.get(&accounts[0]) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };
        claim_ne!(
            voter1.reconstructed_key,
            Vec::<u8>::new(),
            "Voter 1 should have a registered reconstructed key"
        );
        claim_ne!(
            voter1.commitment,
            Vec::<u8>::new(),
            "Voter 1 should have a committed to a vote"
        );

        // Test function briefly for other 2 accounts
        let commitment = off_chain::commit_to_vote(&x2, &g_y2, g_v);

        let commitment_message = CommitMessage {
            reconstructed_key: g_y2.to_bytes().to_vec(),
            commitment,
        };
        let commitment_message_bytes = to_bytes(&commitment_message);

        ctx.set_parameter(&commitment_message_bytes);
        ctx.set_sender(Address::Account(accounts[1]));

        let result = commit(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        let commitment = off_chain::commit_to_vote(&x3, &g_y3, g_v);

        let commitment_message = CommitMessage {
            reconstructed_key: g_y3.to_bytes().to_vec(),
            commitment,
        };
        let commitment_message_bytes = to_bytes(&commitment_message);

        ctx.set_parameter(&commitment_message_bytes);
        ctx.set_sender(Address::Account(accounts[2]));

        let result = commit(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );
    }

    #[concordium_test]
    fn test_vote() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(1));

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = off_chain::create_votingkey_pair();
        let (x2, g_x2) = off_chain::create_votingkey_pair();
        let (x3, g_x3) = off_chain::create_votingkey_pair();

        // Compute reconstructed key
        let keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone()];

        let g_y1 = off_chain::compute_reconstructed_key(&keys, g_x1.clone());
        let g_y2 = off_chain::compute_reconstructed_key(&keys, g_x2.clone());
        let g_y3 = off_chain::compute_reconstructed_key(&keys, g_x3.clone());

        // Testing no vote
        let one_in_two_zkp_account1 =
            off_chain::create_one_in_two_zkp_no(g_x1, g_y1.clone(), x1.clone());
        let vote_message1 = VoteMessage {
            vote: ((g_y1.clone() * x1.clone()) + ProjectivePoint::IDENTITY)
                .to_bytes()
                .to_vec(),
            vote_zkp: one_in_two_zkp_account1,
        };
        let vote_message_bytes = to_bytes(&vote_message1);

        let (state, state_builder) = test_utils::setup_state(
            &accounts,
            vote_config,
            types::VotingPhase::Commit,
        );

        let (mut ctx, mut host) = test_utils::setup_receive_context(
            Some(&vote_message_bytes),
            accounts[0],
            state,
            state_builder,
        );

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x1, &g_y1, ProjectivePoint::IDENTITY),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x2, &g_y2, ProjectivePoint::GENERATOR),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                reconstructed_key: g_y3.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x3, &g_y3, ProjectivePoint::GENERATOR),
                ..Default::default()
            },
        );

        let result = vote(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        // Check that account1 gets refund
        //claim_eq!(Amount::from_micro_ccd(1), "Contract produced wrong action");

        // Check that voter1 has indeed voted
        let voter1 = match host.state().voters.get(&accounts[0]) {
            Some(v) => v,
            None => fail!("Voter 1 should exist"),
        };

        claim_ne!(voter1.vote, Vec::<u8>::new(), "Voter 1 should have voted");

        // Testing yes vote
        let one_two_zkp_account2 =
            off_chain::create_one_in_two_zkp_yes(g_x2, g_y2.clone(), x2.clone());
        let vote_message2 = VoteMessage {
            vote: ((g_y2 * x2) + ProjectivePoint::GENERATOR)
                .to_bytes()
                .to_vec(),
            vote_zkp: one_two_zkp_account2,
        };
        let vote_message_bytes = to_bytes(&vote_message2);
        ctx.set_parameter(&vote_message_bytes);
        ctx.set_sender(Address::Account(accounts[1]));

        let result = vote(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        // Check that account2 gets refund
        // claim_eq!(
        //     actions,
        //     ActionsTree::simple_transfer(&accounts[1], Amount::from_micro_ccd(1)),
        //     "Contract produced wrong action"
        // );
    }

    #[concordium_test]
    fn test_result() {
        let (accounts, vote_config) = test_utils::setup_test_config(4, Amount::from_micro_ccd(1));

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = off_chain::create_votingkey_pair();
        let (x2, g_x2) = off_chain::create_votingkey_pair();
        let (x3, g_x3) = off_chain::create_votingkey_pair();
        let (x4, g_x4) = off_chain::create_votingkey_pair();

        let list_of_voting_keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone(), g_x4.clone()];

        // Compute reconstructed key
        let g_y1 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x1.clone());
        let g_y2 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x2.clone());
        let g_y3 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x3.clone());
        let g_y4 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x4.clone());

        let (state, state_builder) =
            test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Result);

        let (mut ctx, mut host) =
            test_utils::setup_receive_context(None, accounts[0], state, state_builder);

        let mut voters: StateMap<AccountAddress, Voter, _> = host.state_builder().new_map();

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x1, &g_y1, ProjectivePoint::IDENTITY),
                vote: ((g_y1.clone() * x1.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x2, &g_y2, ProjectivePoint::IDENTITY),
                vote: ((g_y2.clone() * x2.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                reconstructed_key: g_y3.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x3, &g_y3, ProjectivePoint::GENERATOR),
                vote: ((g_y3.clone() * x3.clone()) + ProjectivePoint::GENERATOR)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[3],
            Voter {
                reconstructed_key: g_y4.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x4, &g_y4, ProjectivePoint::GENERATOR),
                vote: ((g_y4.clone() * x4.clone()) + ProjectivePoint::GENERATOR)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );

        let result = result(&ctx, &mut host);

        claim!(
            result.is_ok(),
            "Contract receive failed, but should not have"
        );

        claim_eq!((2, 2), host.state().voting_result, "Wrong voting result")
    }

    #[concordium_test]
    fn test_refund_deposits_all_honest() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(1));

        let (state, state_builder) = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Vote);

       
        let (mut ctx, mut host) =
            test_utils::setup_receive_context(None, accounts[0], state, state_builder);
        // Simulate that the 3 voters have registered, commited and voted

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = off_chain::create_votingkey_pair();
        let (x2, g_x2) = off_chain::create_votingkey_pair();
        let (x3, g_x3) = off_chain::create_votingkey_pair();

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                voting_key: g_x1.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                voting_key: g_x2.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                voting_key: g_x3.to_bytes().to_vec(),
                ..Default::default()
            },
        );

        let list_of_voting_keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone()];

        let g_y1 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x1.clone());
        let g_y2 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x2.clone());
        let g_y3 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x3.clone());

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x1, &g_y1, ProjectivePoint::IDENTITY),
                vote: ((g_y1.clone() * x1.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x2, &g_y2, ProjectivePoint::IDENTITY),
                vote: ((g_y2.clone() * x2.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                reconstructed_key: g_y3.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x3, &g_y3, ProjectivePoint::GENERATOR),
                vote: ((g_y3.clone() * x3.clone()) + ProjectivePoint::GENERATOR)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );



        let result = refund_deposits(accounts[0], &mut host);


        claim!(result.is_ok(), "did not refund right amount");
    }

    #[concordium_test]
    fn test_refund_deposits_no_honest() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(1));


        let (state, state_builder) = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Registration);

       
        let (mut ctx, mut host) =
            test_utils::setup_receive_context(None, accounts[0], state, state_builder);

        // Simulate that the 3 voters have registered, but not voted
        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                voting_key: off_chain::create_votingkey_pair().1.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                voting_key: off_chain::create_votingkey_pair().1.to_bytes().to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                voting_key: off_chain::create_votingkey_pair().1.to_bytes().to_vec(),
                ..Default::default()
            },
        );

        let result = refund_deposits(accounts[0], &mut host);

        claim!(result.is_ok(), "suk");
    }

    #[concordium_test]
    fn test_refund_deposits_one_dishonest() {
        let (accounts, vote_config) = test_utils::setup_test_config(3, Amount::from_micro_ccd(1));

        let (state, state_builder) = test_utils::setup_state(&accounts, vote_config, types::VotingPhase::Registration);

       
        let (mut ctx, mut host) =
            test_utils::setup_receive_context(None, accounts[0], state, state_builder);

        // Simulate that the 2 voters have registered, commited and voted

        // Create pk, sk pair of g^x and x for accounts
        let (x1, g_x1) = off_chain::create_votingkey_pair();
        let (x2, g_x2) = off_chain::create_votingkey_pair();
        let (x3, g_x3) = off_chain::create_votingkey_pair();

        let list_of_voting_keys = vec![g_x1.clone(), g_x2.clone(), g_x3.clone()];

        let g_y1 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x1.clone());
        let g_y2 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x2.clone());
        let g_y3 = off_chain::compute_reconstructed_key(&list_of_voting_keys, g_x3.clone());

        host.state_mut().voters.insert(
            accounts[0],
            Voter {
                voting_key: g_x1.to_bytes().to_vec(),
                reconstructed_key: g_y1.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x1, &g_y1, ProjectivePoint::IDENTITY),
                vote: ((g_y1.clone() * x1.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[1],
            Voter {
                voting_key: g_x2.to_bytes().to_vec(),
                reconstructed_key: g_y2.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x2, &g_y2, ProjectivePoint::IDENTITY),
                vote: ((g_y2.clone() * x2.clone()) + ProjectivePoint::IDENTITY)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        );
        host.state_mut().voters.insert(
            accounts[2],
            Voter {
                voting_key: g_x3.to_bytes().to_vec(),
                commitment: off_chain::commit_to_vote(&x3, &g_y3, ProjectivePoint::GENERATOR),
                ..Default::default()
            },
        );

        let result = refund_deposits(accounts[0], &mut host);
         

        claim!(result.is_ok(), "did not refund right amount");
    }
}
