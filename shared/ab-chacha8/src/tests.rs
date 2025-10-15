use crate::{ChaCha8State, block_to_bytes};
use chacha20::cipher::{Iv, StreamCipher};
use chacha20::{ChaCha8, Key, KeyIvInit};

#[test]
fn chacha8_primitive() {
    let seed = [1; 32];

    let mut expected_output = [[0u8; _]; 2];
    ChaCha8::new(&Key::from(seed), &Iv::<ChaCha8>::default())
        .write_keystream(expected_output.as_flattened_mut());

    let initial_state = ChaCha8State::init(&seed, &[0; _]);

    assert_eq!(
        ChaCha8State::from_repr(initial_state.to_repr()).to_repr(),
        initial_state.to_repr()
    );

    assert_eq!(
        block_to_bytes(&initial_state.compute_block(0)),
        expected_output[0]
    );
    assert_eq!(
        block_to_bytes(&initial_state.compute_block(1)),
        expected_output[1]
    );
}
