use futures::executor::block_on;
use rand::prelude::*;
use std::num::{NonZeroU64, NonZeroUsize};
use std::slice;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash};
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::segments::{HistorySize, RecordedHistorySegment};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_farmer_components::plotting::{
    CpuRecordsEncoder, DownloadSectorOptions, EncodeSectorOptions, download_sector, encode_sector,
    write_sector,
};
use subspace_farmer_components::sector::{SectorContentsMap, sector_size};
use subspace_kzg::Kzg;
use subspace_proof_of_space::Table;
use subspace_proof_of_space::chia_v2::ChiaV2Table;

#[test]
fn write_sector_writes_whole_output() {
    let pieces_in_sector = 2;

    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let archived_history_segment = Archiver::new(kzg.clone(), erasure_coding.clone())
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
            true,
        )
        .archived_segments
        .into_iter()
        .next()
        .unwrap();

    let farmer_protocol_info = FarmerProtocolInfo {
        history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
        max_pieces_in_sector: pieces_in_sector,
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    };

    let downloaded_sector = block_on(download_sector(DownloadSectorOptions {
        public_key: &PublicKey::default(),
        sector_index: 0,
        piece_getter: &archived_history_segment,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding: &erasure_coding,
        pieces_in_sector,
    }))
    .unwrap();
    let mut table_generator = ChiaV2Table::generator();
    let encoded_sector = encode_sector(
        downloaded_sector,
        EncodeSectorOptions {
            sector_index: 0,
            records_encoder: &mut CpuRecordsEncoder::<ChiaV2Table>::new(
                slice::from_mut(&mut table_generator),
                &erasure_coding,
                &Default::default(),
            ),
            abort_early: &Default::default(),
        },
    )
    .unwrap();

    let mut sector = Vec::new();
    write_sector(&encoded_sector, &mut sector).unwrap();
    assert_eq!(sector.len(), sector_size(pieces_in_sector));

    // Output of the correct size is overwritten completely
    let mut reused_sector = vec![u8::MAX; sector.len()];
    write_sector(&encoded_sector, &mut reused_sector).unwrap();
    assert_eq!(reused_sector, sector);

    let (sector_contents, sector_checksum) = sector.split_at(sector.len() - Blake3Hash::SIZE);
    assert_eq!(
        sector_checksum,
        AsRef::<[u8]>::as_ref(&blake3_hash(sector_contents))
    );

    let (sector_contents_map_bytes, _) =
        sector.split_at(SectorContentsMap::encoded_size(pieces_in_sector));
    SectorContentsMap::from_bytes(sector_contents_map_bytes, pieces_in_sector).unwrap();
}
