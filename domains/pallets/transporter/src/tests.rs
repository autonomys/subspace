use crate::mock::{
    AccountId, Balance, Balances, MockAccountIdConverter, MockRuntime, RuntimeEvent, RuntimeOrigin,
    SelfChainId, SelfEndpointId, System, Transporter, USER_ACCOUNT, new_test_ext,
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
                    chain_id: SelfChainId::get(),
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
