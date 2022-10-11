use crate::mock::{
    new_test_ext, AccountId, Balances, Event, MockRuntime, Origin, SelfDomainId, System,
    Transporter, USER_ACCOUNT,
};
use crate::{Error, Location, Nonce, Transfer, U256};
use frame_support::traits::Currency;
use frame_support::{assert_err, assert_ok};

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
        System::assert_has_event(Event::Transporter(
            crate::Event::<MockRuntime>::OutgoingTransfer {
                domain_id: dst_domain_id,
                nonce: U256::zero(),
            },
        ));
        assert_eq!(
            Transporter::next_outgoing_transfer_nonce(dst_domain_id),
            U256::one()
        );
        assert_eq!(
            Transporter::outgoing_transfers(dst_domain_id, Nonce::zero()).unwrap(),
            Transfer {
                nonce: Nonce::zero(),
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
