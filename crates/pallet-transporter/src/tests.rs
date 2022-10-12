use crate::mock::{
    new_test_ext, AccountId, Balance, Balances, DomainId, Event, MockRuntime, Origin, SelfDomainId,
    SelfEndpointId, System, Transporter, USER_ACCOUNT,
};
use crate::{EndpointHandler, Error, Location, Transfer};
use codec::Encode;
use frame_support::dispatch::DispatchResult;
use frame_support::traits::Currency;
use frame_support::{assert_err, assert_ok};
use sp_messenger::endpoint::{
    Endpoint, EndpointHandler as EndpointHandlerT, EndpointRequest, EndpointResponse,
};
use std::marker::PhantomData;

#[test]
fn test_initiate_transfer_failed() {
    new_test_ext().execute_with(|| {
        let account = 100;
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 0);

        // transfer 500 to dst_domain id 100
        let dst_domain_id = 1;
        let dst_location = Location {
            domain_id: dst_domain_id,
            account_id: account,
        };
        let res = Transporter::transfer(Origin::signed(account), dst_location, 500);
        assert_err!(res, Error::<MockRuntime>::LowBalance);
    })
}

#[test]
fn test_initiate_transfer() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 1000);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 1000);

        // transfer 500 to dst_domain id 100
        let dst_domain_id = 1;
        let dst_location = Location {
            domain_id: dst_domain_id,
            account_id: account,
        };
        let res = Transporter::transfer(Origin::signed(account), dst_location, 500);
        assert_ok!(res);
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 500);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 500);
        System::assert_has_event(Event::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransferInitiated {
                domain_id: dst_domain_id,
                message_id: 0,
            },
        ));
        assert_eq!(
            Transporter::outgoing_transfers(dst_domain_id, 0).unwrap(),
            Transfer {
                amount: 500,
                sender: Location {
                    domain_id: SelfDomainId::get(),
                    account_id: account
                },
                receiver: Location {
                    domain_id: dst_domain_id,
                    account_id: account
                }
            }
        )
    })
}

#[test]
fn test_transfer_response_missing_request() {
    new_test_ext().execute_with(|| {
        let dst_domain_id: DomainId = 1;
        let amount: Balance = 500;
        let account: AccountId = 100;
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
            receiver: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
        }
        .encode();
        let res = submit_response(dst_domain_id, encoded_payload, Ok(vec![]));
        assert_err!(res, Error::<MockRuntime>::MissingTransferRequest)
    })
}

fn initiate_transfer(dst_domain_id: DomainId, account: AccountId, amount: Balance) {
    let dst_location = Location {
        domain_id: dst_domain_id,
        account_id: account,
    };

    let res = Transporter::transfer(Origin::signed(account), dst_location, amount);
    assert_ok!(res);
    System::assert_has_event(Event::Transporter(
        crate::Event::<MockRuntime>::OutgoingTransferInitiated {
            domain_id: dst_domain_id,
            message_id: 0,
        },
    ));
}

fn submit_response(
    dst_domain_id: DomainId,
    req_payload: Vec<u8>,
    resp: EndpointResponse,
) -> DispatchResult {
    let handler = EndpointHandler(PhantomData::<MockRuntime>::default());
    handler.message_response(
        dst_domain_id,
        0,
        EndpointRequest {
            src_endpoint: Endpoint::Id(SelfEndpointId::get()),
            dst_endpoint: Endpoint::Id(SelfEndpointId::get()),
            payload: req_payload,
        },
        resp,
    )
}

fn submit_transfer(src_domain_id: DomainId, req_payload: Vec<u8>) -> EndpointResponse {
    let handler = EndpointHandler(PhantomData::<MockRuntime>::default());
    handler.message(
        src_domain_id,
        0,
        EndpointRequest {
            src_endpoint: Endpoint::Id(SelfEndpointId::get()),
            dst_endpoint: Endpoint::Id(SelfEndpointId::get()),
            payload: req_payload,
        },
    )
}

#[test]
fn test_transfer_response_invalid_request() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        let amount: Balance = 500;
        // transfer 500 to dst_domain id 100
        let dst_domain_id: DomainId = 1;
        initiate_transfer(dst_domain_id, account, amount);
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
            receiver: Location {
                domain_id: dst_domain_id,
                // change receiver id
                account_id: 100,
            },
        }
        .encode();
        let res = submit_response(dst_domain_id, encoded_payload, Ok(vec![]));
        assert_err!(res, Error::<MockRuntime>::InvalidTransferRequest)
    })
}

#[test]
fn test_transfer_response_revert() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        // transfer 500 to dst_domain id 1
        let amount: Balance = 500;
        let dst_domain_id: DomainId = 1;

        // check pre dispatch balances
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 1000);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 1000);

        // init transfer
        initiate_transfer(dst_domain_id, account, amount);

        // check post init
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 500);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 500);

        // submit response
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
            receiver: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
        }
        .encode();
        let res = submit_response(
            dst_domain_id,
            encoded_payload,
            Err(Error::<MockRuntime>::InvalidPayload.into()),
        );
        assert_ok!(res);

        // balance changes should be reverted.
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 1000);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 1000);
        System::assert_has_event(Event::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransferFailed {
                domain_id: dst_domain_id,
                message_id: 0,
                err: Error::<MockRuntime>::InvalidPayload.into(),
            },
        ));
    })
}

#[test]
fn test_transfer_response_successful() {
    new_test_ext().execute_with(|| {
        let account = USER_ACCOUNT;
        // transfer 500 to dst_domain id 1
        let amount: Balance = 500;
        let dst_domain_id: DomainId = 1;

        // check pre dispatch balances
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 1000);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 1000);

        // init transfer
        initiate_transfer(dst_domain_id, account, amount);

        // check post init
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 500);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 500);

        // submit response
        let encoded_payload = Transfer {
            amount,
            sender: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
            receiver: Location {
                domain_id: dst_domain_id,
                account_id: account,
            },
        }
        .encode();
        let res = submit_response(dst_domain_id, encoded_payload, Ok(vec![]));
        assert_ok!(res);

        // balance changes should be as is.
        let balance = <Balances as Currency<AccountId>>::free_balance(&account);
        assert_eq!(balance, 500);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 500);
        System::assert_has_event(Event::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransferSuccessful {
                domain_id: dst_domain_id,
                message_id: 0,
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
        let src_domain_id: DomainId = 1;

        // check pre dispatch balances
        let balance = <Balances as Currency<AccountId>>::free_balance(&receiver);
        assert_eq!(balance, 0);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 1000);

        let resp = submit_transfer(
            1,
            Transfer {
                amount,
                sender: Location {
                    domain_id: src_domain_id,
                    account_id: 0,
                },
                receiver: Location {
                    domain_id: src_domain_id,
                    account_id: receiver,
                },
            }
            .encode(),
        );
        assert_ok!(resp);
        let balance = <Balances as Currency<AccountId>>::free_balance(&receiver);
        assert_eq!(balance, 500);
        let total_balance = <Balances as Currency<AccountId>>::total_issuance();
        assert_eq!(total_balance, 1500);
    })
}
