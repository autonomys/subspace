use crate::chiapos::table::rmap::Rmap;
use crate::chiapos::table::types::{Position, R};

#[test]
fn test_rmap_basic() {
    let mut rmap = Rmap::new();

    // SAFETY: All `r` values are in `0..PARAM_BC` range
    unsafe {
        assert_eq!(
            rmap.get(R::from(0)),
            [Position::SENTINEL, Position::SENTINEL]
        );

        rmap.add(R::from(0), Position::from(100));
        assert_eq!(
            rmap.get(R::from(0)),
            [Position::from(100), Position::SENTINEL]
        );

        rmap.add(R::from(0), Position::from(101));
        assert_eq!(
            rmap.get(R::from(0)),
            [Position::from(100), Position::from(101)]
        );

        // Ignored as duplicate `r`
        rmap.add(R::from(0), Position::from(102));
        assert_eq!(
            rmap.get(R::from(0)),
            [Position::from(100), Position::from(101)]
        );

        rmap.add(R::from(1), Position::from(200));
        assert_eq!(
            rmap.get(R::from(1)),
            [Position::from(200), Position::SENTINEL]
        );
    }
}

#[test]
fn test_rmap_zero_when_full() {
    let mut rmap = Rmap::new();

    // SAFETY: All `r` values are in `0..PARAM_BC` range
    unsafe {
        rmap.add(R::from(3), Position::from(500));
        rmap.add(R::from(3), Position::from(501));
        // Ignored as duplicate `r`
        rmap.add(R::from(3), Position::from(0));
        assert_eq!(
            rmap.get(R::from(3)),
            [Position::from(500), Position::from(501)]
        );
    }
}
