use crate::rocm::rocm_devices;
use std::num::NonZeroUsize;
use std::slice;
use subspace_core_primitives::hashes::{blake3_254_hash_to_scalar, blake3_hash};
use subspace_core_primitives::pieces::{PieceOffset, Record};
use subspace_core_primitives::sectors::SectorId;
use subspace_core_primitives::segments::HistorySize;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::{CpuRecordsEncoder, RecordsEncoder};
use subspace_farmer_components::sector::SectorContentsMap;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_proof_of_space::Table;

type PosTable = ChiaTable;

#[test]
fn basic() {
    let rocm_device = rocm_devices()
        .into_iter()
        .next()
        .expect("Need ROCm device to run this test");

    let mut table_generator = PosTable::generator();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let global_mutex = Default::default();
    let mut cpu_records_encoder = CpuRecordsEncoder::<PosTable>::new(
        slice::from_mut(&mut table_generator),
        &erasure_coding,
        &global_mutex,
    );

    let history_size = HistorySize::ONE;
    let sector_id = SectorId::new(blake3_hash(b"hello"), 500, history_size);
    let mut record = Record::new_boxed();
    record
        .iter_mut()
        .enumerate()
        .for_each(|(index, chunk)| *chunk = *blake3_254_hash_to_scalar(&index.to_le_bytes()));

    let mut cpu_encoded_records = Record::new_zero_vec(2);
    for cpu_encoded_record in &mut cpu_encoded_records {
        cpu_encoded_record.clone_from(&record);
    }
    let cpu_sector_contents_map = cpu_records_encoder
        .encode_records(&sector_id, &mut cpu_encoded_records, &Default::default())
        .unwrap();

    let mut gpu_encoded_records = Record::new_zero_vec(2);
    for gpu_encoded_record in &mut gpu_encoded_records {
        gpu_encoded_record.clone_from(&record);
    }
    let mut gpu_sector_contents_map = SectorContentsMap::new(2);
    rocm_device
        .generate_and_encode_pospace(
            &sector_id.derive_evaluation_seed(PieceOffset::ZERO),
            &mut gpu_encoded_records[0],
            gpu_sector_contents_map
                .iter_record_bitfields_mut()
                .next()
                .unwrap()
                .iter_mut(),
        )
        .unwrap();
    rocm_device
        .generate_and_encode_pospace(
            &sector_id.derive_evaluation_seed(PieceOffset::ONE),
            &mut gpu_encoded_records[1],
            gpu_sector_contents_map
                .iter_record_bitfields_mut()
                .nth(1)
                .unwrap()
                .iter_mut(),
        )
        .unwrap();

    assert!(cpu_sector_contents_map == gpu_sector_contents_map);
    assert!(cpu_encoded_records == gpu_encoded_records);
}
