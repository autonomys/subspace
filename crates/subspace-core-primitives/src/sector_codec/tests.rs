use crate::sector_codec::SectorCodec;
use crate::Scalar;

#[test]
fn basic() {
    let rows_columns_count = 128_usize;
    let sector_size = rows_columns_count.pow(2) * Scalar::SAFE_BYTES;

    let sector = {
        let mut sector = Vec::with_capacity(sector_size / Scalar::SAFE_BYTES);

        for _ in 0..sector.capacity() {
            sector.push(Scalar::try_from(rand::random::<[u8; 31]>().as_slice()).unwrap());
        }

        sector
    };

    let codec = SectorCodec::new(sector_size).unwrap();

    let mut encoded = sector.clone();
    codec.encode(&mut encoded).unwrap();

    assert_ne!(sector, encoded);

    let mut decoded = encoded.clone();
    codec.decode(&mut decoded).unwrap();

    assert_eq!(sector, decoded);
}
