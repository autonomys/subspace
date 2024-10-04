use crate::cuda::cuda_devices;
use std::num::NonZeroUsize;
use std::slice;
use subspace_core_primitives::crypto::{blake3_254_hash_to_scalar, blake3_hash};
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
    let cuda_device = cuda_devices()
        .into_iter()
        .next()
        .expect("Need CUDA device to run this test");

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

    let sector_id = SectorId::new(blake3_hash(b"hello"), 500);
    let history_size = HistorySize::ONE;
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
        .encode_records(
            &sector_id,
            &mut cpu_encoded_records,
            history_size,
            &Default::default(),
        )
        .unwrap();

    let mut gpu_encoded_records = Record::new_zero_vec(2);
    for gpu_encoded_record in &mut gpu_encoded_records {
        gpu_encoded_record.clone_from(&record);
    }
    let mut gpu_sector_contents_map = SectorContentsMap::new(2);
    cuda_device
        .generate_and_encode_pospace(
            &sector_id.derive_evaluation_seed(PieceOffset::ZERO, history_size),
            &mut gpu_encoded_records[0],
            gpu_sector_contents_map
                .iter_record_bitfields_mut()
                .next()
                .unwrap()
                .iter_mut(),
        )
        .unwrap();
    cuda_device
        .generate_and_encode_pospace(
            &sector_id.derive_evaluation_seed(PieceOffset::ONE, history_size),
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
