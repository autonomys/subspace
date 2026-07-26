use crate::mock::{
    AccountId, Balance, Balances, DomainSelfChainId, MockAccountIdConverter, MockRuntime,
    RuntimeEvent, RuntimeOrigin, SelfEndpointId, System, Transporter, USER_ACCOUNT, new_test_ext,
};
use crate::{EndpointHandler, Error, Location, Transfer};
use domain_runtime_primitives::MultiAccountId;
use frame_support::dispatch::DispatchResult;
use frame_support::{assert_err, assert_ok};
use parity_scale_codec::Encode;
use sp_core::U256;
use sp_messenger::endpoint::{
    Endpoint, EndpointHandler as EndpointHandlerT, EndpointRequest, EndpointResponse,
};
use sp_messenger::messages::{ChainId, MessageId};
use sp_runtime::traits::Convert;
use std::marker::PhantomData;

const MESSAGE_ID: MessageId = (U256::zero(), U256::zero());

#[test]
fn test_initiate_transfer_failed() {
    new_test_ext().execute_with(|| {
        let account = 100;
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 0);

        // transfer 500 to dst_chain id 100
        let dst_chain_id = 1.into();
        let dst_location = Location {
            chain_id: dst_chain_id,
            account_id: MockAccountIdConverter::convert(account),
        };
        let res = Transporter::transfer(RuntimeOrigin::signed(account), dst_location, 500);
        assert_err!(res, Error::<MockRuntime>::LowBalance);
    })
}

#[test]
fn test_initiate_transfer() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 1000);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 1000);

        // transfer 500 to dst_chain id 100
        let dst_chain_id = 1.into();
        let dst_location = Location {
            chain_id: dst_chain_id,
            account_id: MockAccountIdConverter::convert(account),
        };
        let res = Transporter::transfer(RuntimeOrigin::signed(account), dst_location, 500);
        assert_ok!(res);
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 500);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 500);
        System::assert_has_event(RuntimeEvent::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransferInitiated {
                chain_id: dst_chain_id,
                message_id: MESSAGE_ID,
                amount: 500,
            },
        ));
        assert_eq!(
            Transporter::outgoing_transfers(dst_chain_id, MESSAGE_ID).unwrap(),
            Transfer {
                amount: 500,
                sender: Location {
                    chain_id: DomainSelfChainId::get(),
                    account_id: MockAccountIdConverter::convert(account),
                },
                receiver: Location {
                    chain_id: dst_chain_id,
                    account_id: MockAccountIdConverter::convert(account),
                },
            }
        )
    })
}

#[test]
fn test_transfer_response_missing_request() {
    new_test_ext().execute_with(|| {
        let dst_chain_id: ChainId = 1.into();
        let amount: Balance = 500;
        let account: AccountId = 100;
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
            receiver: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
        }
        .encode();
        let res = submit_response(dst_chain_id, encoded_payload, Ok(vec![]));
        assert_err!(res, Error::<MockRuntime>::MissingTransferRequest)
    })
}

fn initiate_transfer(dst_chain_id: ChainId, account: AccountId, amount: Balance) {
    let dst_location = Location {
        chain_id: dst_chain_id,
        account_id: MockAccountIdConverter::convert(account),
    };

    let res = Transporter::transfer(RuntimeOrigin::signed(account), dst_location, amount);
    assert_ok!(res);
    System::assert_has_event(RuntimeEvent::Transporter(
        crate::Event::<MockRuntime>::OutgoingTransferInitiated {
            chain_id: dst_chain_id,
            message_id: MESSAGE_ID,
            amount,
        },
    ));
}

fn submit_response(
    dst_chain_id: ChainId,
    req_payload: Vec<u8>,
    resp: EndpointResponse,
) -> DispatchResult {
    let handler = EndpointHandler(PhantomData::<MockRuntime>);
    handler.message_response(
        dst_chain_id,
        MESSAGE_ID,
        EndpointRequest {
            src_endpoint: Endpoint::Id(SelfEndpointId::get()),
            dst_endpoint: Endpoint::Id(SelfEndpointId::get()),
            payload: req_payload,
        },
        resp,
    )
}

fn submit_transfer(src_chain_id: ChainId, req_payload: Vec<u8>) -> EndpointResponse {
    let handler = EndpointHandler(PhantomData::<MockRuntime>);
    handler.message(
        src_chain_id,
        MESSAGE_ID,
        EndpointRequest {
            src_endpoint: Endpoint::Id(SelfEndpointId::get()),
            dst_endpoint: Endpoint::Id(SelfEndpointId::get()),
            payload: req_payload,
        },
        Ok(()),
    )
}

#[test]
fn test_transfer_response_invalid_request() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        let amount: Balance = 500;
        // transfer 500 to dst_chain id 100
        let dst_chain_id: ChainId = 1.into();
        initiate_transfer(dst_chain_id, account, amount);
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
            receiver: Location {
                chain_id: dst_chain_id,
                // change receiver id
                account_id: MockAccountIdConverter::convert(100),
            },
        }
        .encode();
        let res = submit_response(dst_chain_id, encoded_payload, Ok(vec![]));
        assert_err!(res, Error::<MockRuntime>::InvalidTransferRequest)
    })
}

#[test]
fn test_transfer_invalid_account_id() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        let amount: Balance = 500;
        // transfer 500 to dst_chain id 100
        let dst_chain_id: ChainId = 1.into();
        let dst_location = Location {
            chain_id: dst_chain_id,
            account_id: MultiAccountId::AccountId20([0; 20]),
        };

        let res = Transporter::transfer(RuntimeOrigin::signed(account), dst_location, amount);
        assert_err!(res, Error::<MockRuntime>::InvalidAccountId)
    })
}

#[test]
fn test_transfer_invalid_account_id_substrate() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        let amount: Balance = 500;
        // transfer 500 to dst_chain id 1
        let dst_chain_id: ChainId = 1.into();
        let dst_location = Location {
            chain_id: dst_chain_id,
            account_id: MultiAccountId::AccountId32([0; 32]),
        };

        let res = Transporter::transfer(RuntimeOrigin::signed(account), dst_location, amount);
        assert_err!(res, Error::<MockRuntime>::InvalidAccountId)
    })
}

#[test]
fn test_transfer_response_revert() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        // transfer 500 to dst_chain id 1
        let amount: Balance = 500;
        let dst_chain_id: ChainId = 1.into();

        // check pre dispatch balances
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 1000);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 1000);

        // init transfer
        initiate_transfer(dst_chain_id, account, amount);

        // check post init
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 500);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 500);

        // submit response
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
            receiver: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
        }
        .encode();
        let res = submit_response(
            dst_chain_id,
            encoded_payload,
            Err(Error::<MockRuntime>::InvalidPayload.into()),
        );
        assert_ok!(res);

        // balance changes should be reverted.
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 1000);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 1000);
        System::assert_has_event(RuntimeEvent::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransferFailed {
                chain_id: dst_chain_id,
                message_id: MESSAGE_ID,
                err: Error::<MockRuntime>::InvalidPayload.into(),
            },
        ));
    })
}

#[test]
fn test_transfer_response_successful() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        // transfer 500 to dst_chain id 1
        let amount: Balance = 500;
        let dst_chain_id: ChainId = 1.into();

        // check pre dispatch balances
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 1000);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 1000);

        // init transfer
        initiate_transfer(dst_chain_id, account, amount);

        // check post init
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 500);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 500);

        // submit response
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
            receiver: Location {
                chain_id: dst_chain_id,
                account_id: MockAccountIdConverter::convert(account),
            },
        }
        .encode();
        let res = submit_response(dst_chain_id, encoded_payload, Ok(vec![]));
        assert_ok!(res);

        // balance changes should be as is.
        let balance = Balances::free_balance(account);
        assert_eq!(balance, 500);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 500);
        System::assert_has_event(RuntimeEvent::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransferSuccessful {
                chain_id: dst_chain_id,
                message_id: MESSAGE_ID,
            },
        ));
    })
}

#[test]
fn test_receive_incoming_transfer() {
    new_test_ext().execute_with(|| {
        let receiver = 2;
        // transfer 500
        let amount: Balance = 500;
        let src_chain_id: ChainId = 100.into();
        let dst_chain_id: ChainId = 1.into();

        // check pre dispatch balances
        let balance = Balances::free_balance(receiver);
        assert_eq!(balance, 0);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 1000);

        let resp = submit_transfer(
            src_chain_id,
            Transfer {
                amount,
                sender: Location {
                    chain_id: src_chain_id,
                    account_id: MockAccountIdConverter::convert(0),
                },
                receiver: Location {
                    chain_id: dst_chain_id,
                    account_id: MockAccountIdConverter::convert(receiver),
                },
            }
            .encode(),
        );
        assert_ok!(resp);
        let balance = Balances::free_balance(receiver);
        assert_eq!(balance, 500);
        let total_balance = Balances::total_issuance();
        assert_eq!(total_balance, 1500);
    })
}

#[test]
fn all_domains_supply_defaults_to_zero_and_adjusts() {
    new_test_ext().execute_with(|| {
        assert_eq!(Transporter::all_domains_supply(), 0);
        Transporter::increase_all_domains_supply(100);
        assert_eq!(Transporter::all_domains_supply(), 100);
        Transporter::decrease_all_domains_supply(40);
        assert_eq!(Transporter::all_domains_supply(), 60);
    });
}

#[test]
fn decreasing_all_domains_supply_below_zero_floors_at_zero() {
    new_test_ext().execute_with(|| {
        Transporter::increase_all_domains_supply(60);
        // Decreasing more than is held is drift; it floors at zero (logged) instead of panicking.
        Transporter::decrease_all_domains_supply(1_000);
        assert_eq!(Transporter::all_domains_supply(), 0);
    });
}

mod consensus_tests {
    use super::MESSAGE_ID;
    use crate::mock::consensus::{
        Balances, ConsensusMockRuntime as MockRuntime, RuntimeEvent, RuntimeOrigin, System,
        Transporter, new_test_ext,
    };
    use crate::mock::{
        AccountId, Balance, MockAccountIdConverter, USER_ACCOUNT,
        assert_all_domains_supply_reconciles,
    };
    use crate::{Error, Event, Location};
    use frame_support::{assert_err, assert_ok};
    use sp_domains::{DomainId, DomainsTransfersTracker};
    use sp_messenger::messages::ChainId;
    use sp_runtime::traits::Convert;

    fn initiate_transfer(dst_chain_id: ChainId, account: AccountId, amount: Balance) {
        let dst_location = Location {
            chain_id: dst_chain_id,
            account_id: MockAccountIdConverter::convert(account),
        };
        assert_ok!(Transporter::transfer(
            RuntimeOrigin::signed(account),
            dst_location,
            amount
        ));
        System::assert_has_event(RuntimeEvent::Transporter(
            Event::<MockRuntime>::OutgoingTransferInitiated {
                chain_id: dst_chain_id,
                message_id: MESSAGE_ID,
                amount,
            },
        ));
    }

    #[test]
    fn aggregate_reconciles_across_transfer_lifecycle() {
        new_test_ext().execute_with(|| {
            let d = DomainId::new(0);
            Transporter::initialize_domain_balance(d, 1_000).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();

            // consensus -> domain: in-flight then confirmed
            Transporter::note_transfer(ChainId::Consensus, ChainId::Domain(d), 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            Transporter::confirm_transfer(ChainId::Consensus, ChainId::Domain(d), 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();

            // domain -> consensus: in-flight, rejected, reclaimed
            Transporter::note_transfer(ChainId::Domain(d), ChainId::Consensus, 50).unwrap();
            Transporter::reject_transfer(ChainId::Domain(d), ChainId::Consensus, 50).unwrap();
            Transporter::claim_rejected_transfer(ChainId::Domain(d), ChainId::Consensus, 50)
                .unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();

            // fee reduction
            Transporter::reduce_domain_balance(d, 30).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
        });
    }

    #[test]
    fn credit_supply_invariant_across_consensus_to_domain_transfer() {
        new_test_ext().execute_with(|| {
            let d = DomainId::new(0);
            let credit_supply = || Balances::total_issuance() + Transporter::all_domains_supply();
            let before = credit_supply();

            // real consensus-side transfer: burns on source and notes the in-flight transfer
            initiate_transfer(ChainId::Domain(d), USER_ACCOUNT, 200);
            assert_eq!(
                credit_supply(),
                before,
                "in-flight bucket must offset the consensus burn"
            );

            // confirmation moves the value from the in-flight bucket to the held domain balance
            Transporter::confirm_transfer(ChainId::Consensus, ChainId::Domain(d), 200).unwrap();
            assert_eq!(
                credit_supply(),
                before,
                "held domain balance must keep it invariant"
            );
        });
    }

    #[test]
    fn credit_supply_drops_by_dust_burn_only() {
        new_test_ext().execute_with(|| {
            let d = DomainId::new(0);
            Transporter::initialize_domain_balance(d, 1_000).unwrap();
            let credit_supply = || Balances::total_issuance() + Transporter::all_domains_supply();
            let before = credit_supply();

            let total_fees: Balance = 100;
            let burned: Balance = 10;
            // the fee reduction debits the domain balance from the aggregate ...
            Transporter::reduce_domain_balance(d, total_fees).unwrap();
            // ... and consensus re-mints every fee component except the dust burn
            let rewarded: AccountId = 2;
            let _ = <Balances as frame_support::traits::Currency<AccountId>>::deposit_creating(
                &rewarded,
                total_fees - burned,
            );

            assert_eq!(
                before - credit_supply(),
                burned,
                "only the genuine burn lowers credit supply"
            );
        });
    }

    #[test]
    fn credit_supply_invariant_across_domain_to_consensus_transfer() {
        new_test_ext().execute_with(|| {
            let d = DomainId::new(0);
            Transporter::initialize_domain_balance(d, 1_000).unwrap();
            let credit_supply = || Balances::total_issuance() + Transporter::all_domains_supply();
            let before = credit_supply();

            // domain -> consensus in-flight: debits the domain balance, credits the unconfirmed bucket
            Transporter::note_transfer(ChainId::Domain(d), ChainId::Consensus, 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            assert_eq!(credit_supply(), before);

            // confirm on consensus: aggregate -= 200 while consensus mints 200 to the receiver
            Transporter::confirm_transfer(ChainId::Domain(d), ChainId::Consensus, 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            let receiver: AccountId = 2;
            let _ = <Balances as frame_support::traits::Currency<AccountId>>::deposit_creating(
                &receiver, 200,
            );
            assert_eq!(
                credit_supply(),
                before,
                "consensus mint offsets the aggregate debit"
            );
        });
    }

    #[test]
    fn credit_supply_reconciles_across_consensus_to_domain_reject_and_reclaim() {
        new_test_ext().execute_with(|| {
            let d = DomainId::new(0);

            // consensus -> domain in-flight
            Transporter::note_transfer(ChainId::Consensus, ChainId::Domain(d), 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            // destination rejects: unconfirmed -> cancelled
            Transporter::reject_transfer(ChainId::Consensus, ChainId::Domain(d), 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            // reclaimed on consensus: cancelled cleared, consensus re-mints (aggregate -= 200)
            Transporter::claim_rejected_transfer(ChainId::Consensus, ChainId::Domain(d), 200)
                .unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            assert_eq!(Transporter::all_domains_supply(), 0);
        });
    }

    #[test]
    fn failed_hook_leaves_aggregate_reconciled() {
        new_test_ext().execute_with(|| {
            let d = DomainId::new(0);
            Transporter::initialize_domain_balance(d, 1_000).unwrap();
            Transporter::note_transfer(ChainId::Consensus, ChainId::Domain(d), 200).unwrap();
            assert_all_domains_supply_reconciles::<MockRuntime>();
            let aggregate = Transporter::all_domains_supply();

            // confirm more than is in-flight -> underflow before any mutation; aggregate must not move
            assert_err!(
                Transporter::confirm_transfer(ChainId::Consensus, ChainId::Domain(d), 999)
                    .map_err(sp_runtime::DispatchError::from),
                Error::<MockRuntime>::BalanceUnderflow
            );
            assert_eq!(Transporter::all_domains_supply(), aggregate);
            assert_all_domains_supply_reconciles::<MockRuntime>();

            // note more out of the domain than it holds -> low balance; aggregate must not move
            assert_err!(
                Transporter::note_transfer(ChainId::Domain(d), ChainId::Consensus, 10_000)
                    .map_err(sp_runtime::DispatchError::from),
                Error::<MockRuntime>::LowBalanceOnDomain
            );
            assert_eq!(Transporter::all_domains_supply(), aggregate);
            assert_all_domains_supply_reconciles::<MockRuntime>();
        });
    }

    #[test]
    fn batch_of_mixed_transfers_reconciles() {
        new_test_ext().execute_with(|| {
            let d0 = DomainId::new(0);
            let d1 = DomainId::new(1);
            Transporter::initialize_domain_balance(d0, 5_000).unwrap();
            Transporter::initialize_domain_balance(d1, 3_000).unwrap();

            // A batch mixing both directions, a reject + reclaim, and a fee reduction across two
            // domains, mirroring what pallet-domains `update_domain_transfers` applies from an ER
            // (exercised end to end at the pallet-domains / runtime level).
            Transporter::note_transfer(ChainId::Consensus, ChainId::Domain(d0), 400).unwrap();
            Transporter::note_transfer(ChainId::Domain(d1), ChainId::Consensus, 250).unwrap();
            Transporter::confirm_transfer(ChainId::Consensus, ChainId::Domain(d0), 400).unwrap();
            Transporter::note_transfer(ChainId::Consensus, ChainId::Domain(d1), 100).unwrap();
            Transporter::reject_transfer(ChainId::Consensus, ChainId::Domain(d1), 100).unwrap();
            Transporter::claim_rejected_transfer(ChainId::Consensus, ChainId::Domain(d1), 100)
                .unwrap();
            Transporter::reduce_domain_balance(d0, 60).unwrap();
            Transporter::confirm_transfer(ChainId::Domain(d1), ChainId::Consensus, 250).unwrap();

            assert_all_domains_supply_reconciles::<MockRuntime>();
        });
    }
}
