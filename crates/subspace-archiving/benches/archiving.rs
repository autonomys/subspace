use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::RecordedHistorySegment;

fn criterion_benchmark(c: &mut Criterion) {
    let mut input = RecordedHistorySegment::new_boxed();
    thread_rng().fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg).unwrap();

    c.bench_function("segment-archiving", |b| {
        b.iter(|| {
            archiver.add_block(
                AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
                Default::default(),
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
