use crate::mock::{new_test_ext, Event, Messenger, Origin, System, Test};
use crate::{InitiateChannelParams, U256};
use frame_support::assert_ok;

#[test]
fn test_initiate_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
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
        assert_eq!(Messenger::next_channel_id(domain_id), U256::one());
        assert!(Messenger::channels(domain_id, channel_id).is_some(),);
    });
}
