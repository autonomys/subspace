use super::*;

#[test]
fn test_from_low_high() {
    for num in [0u32, 1, 42, 0x7FFF_FFFF, u32::MAX] {
        let low = num;
        let high = 42u32;
        let correct = (u64::from(high) << u32::BITS) | u64::from(low);
        let u32n = U32N::<2>::from_low_high(low, high);
        assert_eq!(u32n.to_be_bytes(), correct.to_be_bytes());
    }
}

#[test]
fn test_from_u32() {
    for num in [0u32, 1, 42, 0x7FFF_FFFF, u32::MAX] {
        let u32n = U32N::<2>::from(num);
        assert_eq!(u32n.to_be_bytes(), u64::from(num).to_be_bytes());
    }
}

#[test]
fn test_as_u32() {
    for num in [0u32, 1, 42, 0x7FFF_FFFF, u32::MAX] {
        let u32n = U32N::<2>::from_be_bytes(u64::from(num).to_be_bytes());
        assert_eq!(u32n.as_u32(), num);
    }
}

#[test]
fn test_u64_add() {
    let cases = [
        (0u64, 0u64),
        (1, 2),
        (u64::from(u32::MAX), 1),
        (u64::MAX - 1, 1),
    ];
    for &(a, b) in &cases {
        let a_u = U32N::<2>::from_be_bytes(a.to_be_bytes());
        let b_u = U32N::<2>::from_be_bytes(b.to_be_bytes());
        let sum = a + b;
        let sum_u = a_u + b_u;
        assert_eq!(sum.to_be_bytes(), sum_u.to_be_bytes());
    }
}

#[test]
fn test_u64_sub() {
    let cases = [(2u64, 1u64), (u64::MAX, 1), (1, 0)];
    for &(a, b) in &cases {
        let a_u = U32N::<2>::from_be_bytes(a.to_be_bytes());
        let b_u = U32N::<2>::from_be_bytes(b.to_be_bytes());
        let diff = a - b;
        let diff_u = a_u - b_u;
        assert_eq!(diff.to_be_bytes(), diff_u.to_be_bytes());
    }
}

#[test]
fn test_u64_bitwise() {
    let a = 0xFF00_FF00_FF00_FF00_u64;
    let b = 0x00FF_00FF_00FF_00FF_u64;

    let a_u = U32N::<2>::from_be_bytes(a.to_be_bytes());
    let b_u = U32N::<2>::from_be_bytes(b.to_be_bytes());

    assert_eq!((a & b).to_be_bytes(), (a_u & b_u).to_be_bytes());
    assert_eq!((a | b).to_be_bytes(), (a_u | b_u).to_be_bytes());
    assert_eq!((a ^ b).to_be_bytes(), (a_u ^ b_u).to_be_bytes());
}

#[test]
fn test_u64_shifts() {
    let val = 0x0123_4567_89AB_CDEF_u64;
    let val_u = U32N::<2>::from_be_bytes(val.to_be_bytes());

    for shift in 0..64_u32 {
        assert_eq!((val << shift).to_be_bytes(), (val_u << shift).to_be_bytes());
        assert_eq!((val >> shift).to_be_bytes(), (val_u >> shift).to_be_bytes());
    }
}

#[test]
fn test_u64_roundtrip_bytes() {
    let values = [0u64, 1u64, u64::from(u32::MAX), u64::MAX];
    for v in values {
        let bytes = v.to_be_bytes();
        let u = U32N::<2>::from_be_bytes(bytes);
        assert_eq!(bytes, u.to_be_bytes());
    }
}

#[test]
fn test_u128_add() {
    let cases = [
        (0u128, 0u128),
        (1, 2),
        (u128::from(u64::MAX), 1),
        (u128::MAX - 1, 1),
    ];
    for &(a, b) in &cases {
        let a_u = U32N::<4>::from_be_bytes(a.to_be_bytes());
        let b_u = U32N::<4>::from_be_bytes(b.to_be_bytes());
        let sum = a + b;
        let sum_u = a_u + b_u;
        assert_eq!(sum.to_be_bytes(), sum_u.to_be_bytes());
    }
}

#[test]
fn test_u128_sub() {
    let cases = [(2u128, 1u128), (u128::MAX, 1), (1, 0)];
    for &(a, b) in &cases {
        let a_u = U32N::<4>::from_be_bytes(a.to_be_bytes());
        let b_u = U32N::<4>::from_be_bytes(b.to_be_bytes());
        let diff = a - b;
        let diff_u = a_u - b_u;
        assert_eq!(diff.to_be_bytes(), diff_u.to_be_bytes());
    }
}

#[test]
fn test_u128_bitwise() {
    let a = 0xFF00_FF00_FF00_FF00_FF00_FF00_FF00_FF00_u128;
    let b = 0x00FF_00FF_00FF_00FF_00FF_00FF_00FF_00FF_u128;

    let a_u = U32N::<4>::from_be_bytes(a.to_be_bytes());
    let b_u = U32N::<4>::from_be_bytes(b.to_be_bytes());

    assert_eq!((a & b).to_be_bytes(), (a_u & b_u).to_be_bytes());
    assert_eq!((a | b).to_be_bytes(), (a_u | b_u).to_be_bytes());
    assert_eq!((a ^ b).to_be_bytes(), (a_u ^ b_u).to_be_bytes());
}

#[test]
fn test_u128_shifts() {
    let val = 0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF_u128;
    let val_u = U32N::<4>::from_be_bytes(val.to_be_bytes());

    for shift in 0..128_u32 {
        assert_eq!((val << shift).to_be_bytes(), (val_u << shift).to_be_bytes());
        assert_eq!((val >> shift).to_be_bytes(), (val_u >> shift).to_be_bytes());
    }
}

#[test]
fn test_u128_roundtrip_bytes() {
    let values = [0u128, 1u128, u128::from(u64::MAX), u128::MAX];
    for v in values {
        let bytes = v.to_be_bytes();
        let u = U32N::<4>::from_be_bytes(bytes);
        assert_eq!(bytes, u.to_be_bytes());
    }
}

#[test]
fn test_as_be_bytes_to_le_u32_words() {
    let values = [
        0u128,
        1,
        u128::from(u32::MAX),
        u128::from(u64::MAX),
        u128::MAX,
        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
    ];

    for v in values {
        let u = U32N::<4>::from_be_bytes(v.to_be_bytes());
        let words = u.as_be_bytes_to_le_u32_words();

        let bytes = v.to_be_bytes();
        let expected = [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        ];

        assert_eq!(words, expected, "v={v}");
    }
}

#[test]
fn test_from_le_u32_words_as_be_bytes() {
    let values = [
        0u128,
        1,
        u128::from(u32::MAX),
        u128::from(u64::MAX),
        u128::MAX,
        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
    ];

    for &v in &values {
        let u = U32N::<4>::from_be_bytes(v.to_be_bytes());
        let words = u.as_be_bytes_to_le_u32_words();
        let reconstructed = U32N::<4>::from_le_u32_words_as_be_bytes(&words);

        assert_eq!(u.to_be_bytes(), reconstructed.to_be_bytes(), "v={v}");
    }
}
