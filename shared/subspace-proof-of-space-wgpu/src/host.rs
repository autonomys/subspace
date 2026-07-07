//! Host side: runs GPU proof generation and encodes records with subspace's KZG scheme, so a
//! GPU-plotted sector reads back byte-for-byte the same as the CPU encoder.

use ab_proof_of_space_gpu::GpuRecordsEncoderInstance;
use std::ops::DerefMut;
use std::simd::Simd;
use subspace_core_primitives::ScalarBytes;
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::pos::PosSeed;
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Scalar;

/// A single wgpu proof-of-space encoder (one GPU queue) plus the erasure coding used to encode
/// records host-side.
pub struct WgpuDevice {
    instance: GpuRecordsEncoderInstance,
    erasure_coding: ErasureCoding,
}

impl WgpuDevice {
    /// Create a new device from an abundance proof encoder instance.
    pub fn new(instance: GpuRecordsEncoderInstance, erasure_coding: ErasureCoding) -> Self {
        Self {
            instance,
            erasure_coding,
        }
    }

    /// Generate proofs on the GPU and encode a record with subspace's KZG scheme.
    ///
    /// Mirrors `record_encoding` in `subspace-farmer-components`, so output is byte-identical to
    /// the CPU encoder.
    pub fn generate_and_encode_pospace(
        &mut self,
        seed: &PosSeed,
        record: &mut Record,
        encoded_chunks_used_output: impl ExactSizeIterator<Item = impl DerefMut<Target = bool>>,
    ) -> Result<(), String> {
        let proofs = self
            .instance
            .create_proofs(seed)
            .map_err(|error| error.to_string())?;
        let proofs = proofs.proofs();

        let source_record_chunks = record.to_vec();
        let parity_record_chunks = self
            .erasure_coding
            .extend(
                &source_record_chunks
                    .iter()
                    .map(|scalar_bytes| {
                        Scalar::try_from(scalar_bytes)
                            .expect("Record chunks are valid scalar bytes; qed")
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("Erasure coding instance supports this many shards; qed")
            .into_iter()
            .map(<[u8; ScalarBytes::FULL_BYTES]>::from)
            .collect::<Vec<_>>();

        let mut encoded_chunks_used = vec![false; Record::NUM_S_BUCKETS];
        let mut chunks_scratch =
            Vec::<[u8; ScalarBytes::FULL_BYTES]>::with_capacity(Record::NUM_S_BUCKETS);
        for s_bucket in 0..Record::NUM_S_BUCKETS {
            let record_chunk = if s_bucket % 2 == 0 {
                &source_record_chunks[s_bucket / 2]
            } else {
                &parity_record_chunks[s_bucket / 2]
            };

            let proof_found = (proofs.found_proofs[s_bucket / u8::BITS as usize]
                >> (s_bucket % u8::BITS as usize))
                & 1
                == 1;
            let encoded_chunk = if proof_found {
                (Simd::from(*record_chunk) ^ Simd::from(*proofs.proofs[s_bucket].hash())).to_array()
            } else {
                // Dummy value indicating no proof
                [0; ScalarBytes::FULL_BYTES]
            };
            chunks_scratch.push(encoded_chunk);
        }

        let num_successfully_encoded_chunks = chunks_scratch
            .drain(..)
            .zip(encoded_chunks_used.iter_mut())
            .filter_map(|(maybe_encoded_chunk, encoded_chunk_used)| {
                if maybe_encoded_chunk == [0; ScalarBytes::FULL_BYTES] {
                    None
                } else {
                    *encoded_chunk_used = true;
                    Some(maybe_encoded_chunk)
                }
            })
            .take(record.len())
            .zip(record.iter_mut())
            .map(|(input_chunk, output_chunk)| {
                *output_chunk = input_chunk;
            })
            .count();

        source_record_chunks
            .iter()
            .zip(&parity_record_chunks)
            .flat_map(|(a, b)| [a, b])
            .zip(encoded_chunks_used.iter())
            .filter_map(|(record_chunk, encoded_chunk_used)| {
                if *encoded_chunk_used {
                    None
                } else {
                    Some(record_chunk)
                }
            })
            .zip(record.iter_mut().skip(num_successfully_encoded_chunks))
            .for_each(|(input_chunk, output_chunk)| {
                *output_chunk = *input_chunk;
            });

        encoded_chunks_used_output
            .zip(&encoded_chunks_used)
            .for_each(|(mut output, input)| *output = *input);

        Ok(())
    }
}
