//! Virtual-to-physical mapping table tests.

use crate::chiapos::table::rmap::Rmap;
use crate::chiapos::table::types::{Position, R};

#[test]
fn test_rmap_basic() {
    let mut rmap = Rmap::new();

    unsafe {
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
fn test_rmap_zero_position() {
    let mut rmap = Rmap::new();

    unsafe {
        // Position zero should be stored correctly
        rmap.add(R::from(2), Position::from(0));
        assert_eq!(
            rmap.get(R::from(2)),
            [Position::from(0), Position::SENTINEL]
        );

        rmap.add(R::from(2), Position::from(400));
        assert_eq!(
            rmap.get(R::from(2)),
            [Position::from(0), Position::from(400)]
        );
    }
}

#[test]
fn test_rmap_zero_when_full() {
    let mut rmap = Rmap::new();

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

#[test]
fn test_rmap_no_entry() {
    let rmap = Rmap::new();

    unsafe {
        // Querying an `r` that was never added returns SENTINEL
        assert_eq!(
            rmap.get(R::from(5)),
            [Position::SENTINEL, Position::SENTINEL]
        );
    }
}
