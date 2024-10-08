// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <fstream>
#include <cstdint>
#define FEATURE_BLS12_381
#include <ff/bls12-381.hpp>
#include <util/gpu_t.cuh>
#include <util/rusterror.h>
#include <ntt/ntt.cuh>
#include <errno.h>

const uint32_t PARAM_EXT = 6;
const uint32_t PARAM_M = 1u << PARAM_EXT;
const uint32_t PARAM_B = 119;
const uint32_t PARAM_C = 127;
const uint32_t PARAM_BC = 15113; // PARAM_B * PARAM_C
const size_t PAGE_SIZE = 4096;

#include "common_operations.cuh"
#include "chacha.cuh"
#include "data_structures.cuh"
#include "sort15113.cuh"
#include "blake3.cuh"
#include "create_tables.cuh"
#include "find_proof.cuh"
#include "find_matches.cuh"

// Returns the number of available GPUs
extern "C" {
    size_t gpu_count() {
        return ngpus();
    }
}

template<int K>
void create_tables(gpu_specific_state& gpu_state, const chacha_state& state,
                   uint32_t output_block_count, uint32_t table_size, size_t shared_sz,
                   size_t shared_sz_matches, const int y_bit_size, uint32_t nbuckets,
                   uint32_t* d_match_counter)
{
    const gpu_t& gpu = gpu_state.gpu;

    //------------------------First Table-----------------------
    // Generates the ChaCha key stream for the first table.
    generate_chacha_keystream<8><<<gpu.sm_count(), 1024, 0, gpu>>>
        (gpu_state.out_chacha, state, output_block_count);

    CUDA_OK(cudaGetLastError());

    // Computes the `y` values for the first table.
    compute_f1<K, PARAM_EXT><<<gpu.sm_count(), 1024, 0, gpu>>>
        (gpu_state.tables[0].y, (uint32_t*)&gpu_state.out_chacha[0], table_size);

    CUDA_OK(cudaGetLastError());

    // Sorts the first table.
    gpu.launch_coop(sort15113, launch_params_t{gpu.sm_count(), SORT_BLOCKDIM, shared_sz},
                    &gpu_state.tables[0].ys[0],
                    (const uint32_t*)gpu_state.tables[0].y,
                    table_size, &gpu_state.temp_sort[0],
                    &gpu_state.histogram[0], false, y_bit_size);

    //------------------------Other Tables-----------------------
    for (size_t i = 1; i < NUM_TABLES; i++) {
        // Resets the match counter for the current table.
        gpu.bzero(&d_match_counter[0], 1);
        metadata* metadatas_input = gpu_state.tables[i - 1].metadatas;

        // Finds matches for the current table.
        find_matches<<<nbuckets - 1, block_sz, shared_sz_matches * sizeof(uint32_t), gpu>>>
            (&gpu_state.tables[i].matches[0], gpu_state.tables[i - 1].ys,
             &gpu_state.histogram[0], &d_match_counter[0]);

        CUDA_OK(cudaGetLastError());

        // Computes the `y` for the current table.
        compute_fn<K, PARAM_EXT><<<gpu.sm_count(), 1024, 0, gpu>>>
            (gpu_state.tables[i].y, gpu_state.tables[i].metadatas,
             gpu_state.tables[i - 1].ys, gpu_state.tables[i - 1].y,
             gpu_state.tables[i].matches, &d_match_counter[0],
             metadatas_input, i + 1);

        CUDA_OK(cudaGetLastError());

        // Sorts the current table.
        gpu.launch_coop(sort15113, launch_params_t{gpu.sm_count(), SORT_BLOCKDIM, shared_sz},
                        &gpu_state.tables[i].ys[0], (const uint32_t*)gpu_state.tables[i].y,
                        (const uint32_t*)&d_match_counter[0],
                        &gpu_state.temp_sort[0], &gpu_state.histogram[0],
                        i == NUM_TABLES - 1, y_bit_size);
    }
}

// This function generates and encodes PoSpace on the GPU,
// specifically calculating the chunks_scratch vector.
template <uint32_t K>
RustError::by_value generate_and_encode_pospace(const uint8_t* key,
                                                uint32_t lg_record_size,
                                                uint32_t* challenge_index,
                                                const fr_t* record,
                                                uint8_t* chunks_scratch,
                                                uint32_t* proof_count,
                                                fr_t* parity_record_chunks,
                                                int gpu_id)
{
    const int y_bit_size = K + PARAM_EXT;

    uint32_t record_size = 1 << lg_record_size;
    uint32_t challenge_len = record_size << 1;

    size_t output_len_bytes = K * ((size_t)1 << K) / 8;
    size_t output_block_count = output_len_bytes / 64;

    uint32_t table_size = 1 << K;
    size_t shared_sz = sizeof(uint32_t) << DIGIT_BITS;

    // nonce is initialized as a 12-byte array with all zeros.
    uint8_t nonce[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    // Initializes the ChaCha state with the key and nonce.
    chacha_state state = initialize_chacha_state<uint32_t>(key, nonce);

    uint32_t nbuckets = (1u << y_bit_size) / PARAM_BC + 1;
    size_t shared_sz_matches = (NUM_TABLES - 1) * block_sz * sizeof(uint2) / sizeof(uint32_t) + 512;

    // Gets the GPU-specific state for the given GPU_ID.
    gpu_specific_state& gpu_state = proof_state.gpu_specific_states[gpu_id];
    // Locks the mutex for the specific GPU identified by GPU_ID.
    std::lock_guard<std::mutex> lock(*gpu_state.mtx);

    // Gets the GPU object.
    const gpu_t& gpu = select_gpu(gpu_id);

    semaphore_t complete;
    gpu.spawn([=, &complete]() {
        struct vm {
            static void touch(const void *ptr, size_t len)
            {
                auto* data = reinterpret_cast<const volatile char*>(ptr);
                for (size_t i = 0; i < len; i += PAGE_SIZE) {
                    data[i];
                }
                data[len - 1];
            }
        };

        vm::touch(parity_record_chunks, record_size * sizeof(fr_t));
        vm::touch(challenge_index, challenge_len * sizeof(uint32_t));
        vm::touch(chunks_scratch, challenge_len * 32);
        complete.notify();
    });

    try {
        // An object to help us sync different asynchronous streams
        event_t sync_event;

        // Allocates and initializes various data on the GPU.

        // Initializes the GPU state.
        gpu_state.initialize_data(K, challenge_len);

        dev_ptr_t<uint32_t> d_match_counter(1, gpu);
        gpu.bzero(&d_match_counter[0], 1);

        dev_ptr_t<uint32_t> d_proof_counter(1, gpu);
        gpu.bzero(&d_proof_counter[0], 1);

        table_data_ptr tables_data[NUM_TABLES];
        for (uint32_t i = 0; i < NUM_TABLES; i++) {
            tables_data[i] = gpu_state.tables[i].get_table_data();
        }

        dev_ptr_t<table_data_ptr> d_tables(NUM_TABLES, gpu);
        gpu.HtoD(&d_tables[0], tables_data, NUM_TABLES);

        dev_ptr_t<uint32_t> d_chunks_scratch(challenge_len * 8);

        dev_ptr_t<fr_t> d_record{2 * record_size, gpu};
        gpu.HtoD(&d_record[record_size], record, record_size);

        // End of GPU data allocation and initialization.

        // Convert the inputs from big-endian into little-endian
        kern_endianness_swap<fr_t><<<gpu.sm_count(), 1024, 0, gpu>>>(&d_record[record_size],
                                                                     &d_record[record_size],
                                                                     record_size);
        
        CUDA_OK(cudaGetLastError());

        // Converts and duplicates data on the GPU.
        convert_to_mont<fr_t><<<gpu.sm_count(), 1024, 0, gpu>>>(&d_record[record_size],
                                                                &d_record[record_size],
                                                                record_size);

        CUDA_OK(cudaGetLastError());

        // Performs inverse NTT on the data in d_record with a given lg_record_size.
        NTT::Base_dev_ptr(gpu, &d_record[record_size], lg_record_size,
                          NTT::InputOutputOrder::NR, NTT::Direction::inverse,
                          NTT::Type::standard);

        NTT::LDE_expand(gpu, &d_record[0], &d_record[record_size], lg_record_size, 1);

        // Performs forward NTT on the data in d_record with a (lg_record_size + 1).
        NTT::Base_dev_ptr(gpu, d_record, lg_record_size + 1,
                          NTT::InputOutputOrder::RN, NTT::Direction::forward,
                          NTT::Type::standard);
        
        // Convert the inputs (and outputs) back to big-endian
        kern_endianness_swap<fr_t><<<gpu.sm_count(), 1024, 0, gpu>>>(&d_record[0],
                                                                     &d_record[0],
                                                                     2 * record_size);
        
        CUDA_OK(cudaGetLastError());

        // Record a list of pending operations submitted to the stream
        sync_event.record(gpu);

        // Creates all NUM_TABLES tables
        create_tables<K>(gpu_state, state, output_block_count, table_size,
                         shared_sz, shared_sz_matches, y_bit_size, nbuckets,
                         d_match_counter);

        // Finds proof and creates chunks scratch
        create_chunks_scratch<K, PARAM_EXT><<<gpu.sm_count(), 256, 0, gpu>>>
            (d_chunks_scratch, &d_proof_counter[0], gpu_state.challenge_index,
             challenge_len, d_record, d_tables, &d_match_counter[0]);

        CUDA_OK(cudaGetLastError());

        // Wait for the list of operations which were recorded to complete
        // before launching any operations on stream gpu[0]
        // The goal is to overlap the next memory copy with create table and find proof kernels
        sync_event.wait(gpu[0]);

        // Creates parity record chunks by transferring odd-indexed elements.
        gpu[0].DtoH(parity_record_chunks, &d_record[1], record_size, 2*sizeof(fr_t));

        // Transfers the proof count from the GPU to the host.
        gpu.DtoH(&proof_count[0], &d_proof_counter[0], 1);

        // Transfers the challenge indices from the GPU to the host.
        gpu.DtoH(challenge_index, gpu_state.challenge_index, proof_count[0]);

        // Transfers the chunks scratch data from the GPU to the host.
        gpu.DtoH((uint32_t*)chunks_scratch, d_chunks_scratch, proof_count[0] * 8);

        // Automatically syncs gpu[0] as well
        gpu.sync();
        complete.wait();
    } catch (const cuda_error& e) {
        gpu.sync();
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
        return RustError{e.code(), e.what()};
#else
        return RustError{e.code()};
#endif
    }

    return RustError{cudaSuccess};
}

// This function calls a templated version of `generate_and_encode_pospace` based on the value of K.
// The support for K values is limited to a maximum of 21 due to constraints in the sorting implementation.
// Specifically, the algorithm calculates an "upper digit" based on the bit length of the data being sorted, divided by PARAM_BC.
// The upper digit has a maximum allowable value of 2^14.
// As K increases, the bit length of the data also increases.
// When K reaches 22, the calculated upper digit exceeds the 2^14 limit.
// Consequently, to ensure correct operation, the algorithm is restricted to K values of 21 or less.
extern "C"
RustError::by_value generate_and_encode_pospace_dispatch(uint32_t K,
                                                         const uint8_t* key,
                                                         uint32_t lg_record_size,
                                                         uint32_t* challenge_index,
                                                         const fr_t* record,
                                                         uint8_t* chunks_scratch,
                                                         uint32_t* proof_count,
                                                         fr_t* parity_record_chunks,
                                                         int gpu_id)
{
    switch (K) {
        case 15: return generate_and_encode_pospace<15>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        case 16: return generate_and_encode_pospace<16>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        case 17: return generate_and_encode_pospace<17>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        case 18: return generate_and_encode_pospace<18>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        case 19: return generate_and_encode_pospace<19>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        case 20: return generate_and_encode_pospace<20>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        case 21: return generate_and_encode_pospace<21>(key, lg_record_size,
                                                        challenge_index, record,
                                                        chunks_scratch, proof_count,
                                                        parity_record_chunks, gpu_id);
        default: return RustError{EINVAL};
    }
}
