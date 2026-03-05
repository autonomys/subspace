//! Virtual-to-physical mapping table tests.

use crate::chiapos::table::rmap::Rmap;
use crate::chiapos::table::types::{Position, R};

#[test]
fn test_rmap_basic() {
    let mut rmap = Rmap::new();

    unsafe {
        rmap.add(R::from(0), Position::from(100));
        assert_eq!(rmap.get(R::from(0)), &[Position::from(100)]);

        rmap.add(R::from(0), Position::from(101));
        assert_eq!(
            rmap.get(R::from(0)),
            &[Position::from(100), Position::from(101)]
        );

        // Third entry — now supported
        rmap.add(R::from(0), Position::from(102));
        assert_eq!(
            rmap.get(R::from(0)),
            &[Position::from(100), Position::from(101), Position::from(102)]
        );

        rmap.add(R::from(1), Position::from(200));
        assert_eq!(rmap.get(R::from(1)), &[Position::from(200)]);
    }
}

#[test]
fn test_rmap_zero_position() {
    let mut rmap = Rmap::new();

    unsafe {
        rmap.add(R::from(2), Position::from(0));
        assert_eq!(rmap.get(R::from(2)), &[Position::from(0)]);

        rmap.add(R::from(2), Position::from(400));
        assert_eq!(
            rmap.get(R::from(2)),
            &[Position::from(0), Position::from(400)]
        );
    }
}

#[test]
fn test_rmap_no_entry() {
    let rmap = Rmap::new();

    unsafe {
        assert!(rmap.get(R::from(5)).is_empty());
    }
}

#[test]
fn test_rmap_supports_three_plus_entries() {
    let mut rmap = Rmap::new();

    unsafe {
        // Simulate 5 non-consecutive entries for the same r-value
        rmap.add(R::from(42), Position::from(10));
        rmap.add(R::from(42), Position::from(500));
        rmap.add(R::from(42), Position::from(1234));
        rmap.add(R::from(42), Position::from(9999));
        rmap.add(R::from(42), Position::from(50000));

        let positions = rmap.get(R::from(42));
        assert_eq!(
            positions,
            &[
                Position::from(10),
                Position::from(500),
                Position::from(1234),
                Position::from(9999),
                Position::from(50000),
            ]
        );
    }
}

#[test]
fn test_rmap_multiple_r_values() {
    let mut rmap = Rmap::new();

    unsafe {
        rmap.add(R::from(10), Position::from(0));
        rmap.add(R::from(10), Position::from(1));
        rmap.add(R::from(10), Position::from(2));

        rmap.add(R::from(20), Position::from(50));
        rmap.add(R::from(20), Position::from(51));

        rmap.add(R::from(30), Position::from(99));

        assert_eq!(
            rmap.get(R::from(10)),
            &[Position::from(0), Position::from(1), Position::from(2)]
        );
        assert_eq!(
            rmap.get(R::from(20)),
            &[Position::from(50), Position::from(51)]
        );
        assert_eq!(rmap.get(R::from(30)), &[Position::from(99)]);
        assert!(rmap.get(R::from(40)).is_empty());
    }
}

