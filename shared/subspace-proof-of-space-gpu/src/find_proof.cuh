// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

__device__ __forceinline__
uint32_t search_min_left_pos(table_data_ptr table, uint32_t dest,
                             uint32_t num_elems, uint32_t shift_amount)
{
    uint32_t left = 0, right = num_elems;

    // Binary search to find the first matching element
    while (left < right) {
        uint32_t middle = (left + right) / 2;

        if ((table.ys[middle].y >> shift_amount) < dest)
            left = middle + 1;
        else
            right = middle;
    }

    // Find the smallest left position among elements with the same y_value
    uint32_t y_value = table.ys[left].y;
    uint32_t smallest_left_pos = UINT32_MAX;
    uint32_t first_matching_element = left;

    for (uint32_t i = left; i < num_elems && table.ys[i].y == y_value; ++i) {
        uint2 match = table.matches[table.ys[i].x];
        if (match.x < smallest_left_pos) {
            smallest_left_pos = match.x;
            first_matching_element = i;
        }
    }

    return first_matching_element;
}

// Packs specified bits from a source uint32 array to a destination byte array.
__device__ __forceinline__
void pack_bits(uint8_t* dest, uint32_t bit_offset, uint32_t value, uint32_t num_bits)
{
    // Starting byte index in the destination
    uint32_t byte_index = bit_offset / 8;
    // Start bit position within the first byte
    uint32_t start_bit = bit_offset % 8;
    // Align bits for extraction
    value <<= (32 - num_bits - start_bit);

    // Pack bits into the destination array
    for (uint32_t i = 0; i < (num_bits + 7) / 8; i++) {
        dest[byte_index + i] |= (value >> (24 - i * 8)) & 0xFF;
    }
}

// This device function packs bits from the source indices into a byte array,
// ready for final proof output.
__device__ __forceinline__
void generate_proof(uint8_t* proof_out, const uint32_t* current_indices,
                    const table_data_ptr* tables, int K)
{
    for (uint32_t offset = 0; offset < 64; offset += 2) {
        uint32_t match_index = tables[1].ys[current_indices[offset / 2]].x;
        uint32_t xs[2] = { tables[0].ys[tables[1].matches[match_index].x].x,
                           tables[0].ys[tables[1].matches[match_index].y].x };

        for (uint32_t j = 0; j < 2; j++) {
            uint32_t bit_offset = K * (offset + j);
            uint32_t value = xs[j];
            pack_bits(proof_out, bit_offset, value, K);
        }
    }
}

// This device function traces back through the tables
// to find left and right positions for a given challenge.
// It updates the `current_indices` array with the matching indices from each table.
__device__ __forceinline__
void trace_back_tables(uint32_t* current_indices, const table_data_ptr* tables,
                       uint32_t num_tables)
{
    for (uint32_t table_number = num_tables - 1; table_number > 1; table_number--) {
        uint32_t depth = 1 << (num_tables - 1 - table_number);
        table_data_ptr table = tables[table_number];

        for (uint32_t j = 0; j < depth && depth < (1 << num_tables); j++) {
            uint32_t base_index = 2 * (depth - j - 1);
            uint32_t current_index = current_indices[depth - j - 1];

            uint32_t match_index = table.ys[current_index].x;
            uint2 match = table.matches[match_index];

            current_indices[base_index] = match.x;
            current_indices[base_index + 1] = match.y;
        }
    }
}

template<int K, int PARAM_EXT>
__global__ __launch_bounds__(256)
void create_chunks_scratch(uint32_t* chunks_scratch, uint32_t* proof_counter,
                           uint32_t* challenge_index, uint32_t challenge_count,
                           fr_t* record, table_data_ptr tables[NUM_TABLES],
                           const uint32_t* table7_size)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;

    for (uint32_t i = tid; i < challenge_count; i += gridDim.x * blockDim.x) {
        uint32_t first_k_challenge_bits = byte_swap(i);
        first_k_challenge_bits >>= (32 - K);

        uint32_t shift_amount = (32 - (K + PARAM_EXT));
        table_data_ptr last_table = tables[NUM_TABLES-1];
        uint32_t first_matching_element
            = search_min_left_pos(last_table, first_k_challenge_bits,
                                  *table7_size, shift_amount);

        if(first_matching_element < *table7_size &&
              (tables[NUM_TABLES - 1].ys[first_matching_element].y >> PARAM_EXT) == first_k_challenge_bits) {

            uint32_t current_indices[1 << (NUM_TABLES - 2)] = {first_matching_element};
            trace_back_tables(current_indices, tables, NUM_TABLES);

            uint8_t proof_out[8 * K] = {0};
            generate_proof(proof_out, current_indices, tables, K);

            // Determine the appropriate record chunk based on the index
            // and convert the record chunk from Montgomery form
            // While two endianness swaps are redundant, we do this so that
            // we queue up an endianness swap kernel just after NTTs, allowing
            // us to overlap a device to host copy which nets us a significant
            // performance gain
            fr_t record_chunk = record[i];
            record_chunk = endianness_swap(record_chunk);
            record_chunk.from();
            record_chunk = endianness_swap(record_chunk);

            // Calculate where to store the chunks_scratch in the output array
            uint32_t proof_offset = atomicAdd(proof_counter, 1);

            // Perform BLAKE3 hashing on the proof
            blake3_state state = blake3_update(proof_out, (8 * K));

            // XOR the record chunk with the hashed proof and store in chunks_scratch
            for (uint32_t index = 0; index < 8; index++) {
                chunks_scratch[proof_offset * 8 + index] = record_chunk[index] ^ state.data[index];
            }

            // Store the corresponding challenge in the challenge_index array
            challenge_index[proof_offset] = i;
        }
    }
}
