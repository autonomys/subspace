use crate::mock::{new_test_ext, DomainId, Event, Messenger, Origin, System, Test};
use crate::{ChannelId, ChannelState, Error, InitiateChannelParams, U256};
use frame_support::{assert_err, assert_ok};

fn create_channel(domain_id: DomainId, channel_id: ChannelId) {
    assert_ok!(Messenger::initiate_channel(
        Origin::root(),
        domain_id,
        InitiateChannelParams {
            max_outgoing_messages: 100,
        },
    ));

    System::assert_last_event(Event::Messenger(crate::Event::<Test>::ChannelInitiated {
        domain_id,
        channel_id,
    }));
    assert_eq!(
        Messenger::next_channel_id(domain_id),
        channel_id.checked_add(U256::one()).unwrap()
    );

    let channel = Messenger::channels(domain_id, channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Initiated);
}

#[test]
fn test_initiate_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id)
    });
}

#[test]
fn test_close_missing_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Test>::MissingChannel
        );
    });
}

#[test]
fn test_close_not_open_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id);
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Test>::InvalidChannelState
        );
    });
}

#[test]
fn test_close_open_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::open_channel(domain_id, channel_id));

        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);

        assert_ok!(Messenger::close_channel(
            Origin::root(),
            domain_id,
            channel_id,
        ));

        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed);
    });
}
