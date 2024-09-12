// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <util/gpu_t.cuh>
#include <util/exception.cuh>

// Specifies the number of tables.
const uint32_t NUM_TABLES = 7;

// Stores 128-bit data and includes device functions for byte swapping,
// computing size in bits, and bitwise shift operations.
class __align__(16) metadata {
public:
    uint64_t data[2];
    static const uint32_t limb_bits = sizeof(uint64_t) * 8;
    static const uint32_t bits = sizeof(data) * 8;

    __device__
    void byte_swap(uint64_t* out_metadata)
    {
        uint8_t* out_bytes = reinterpret_cast<uint8_t*>(out_metadata);
        uint8_t* in_bytes = reinterpret_cast<uint8_t*>(data);
        for (uint32_t i = 0; i < 16; i++) {
            out_bytes[i] = in_bytes[15 - i];
        }
    }

    static __device__
    uint32_t size_bits(int k, int table_number)
    {
        int scale;
        switch (table_number) {
            case 1: scale = 1; break;
            case 2: scale = 2; break;
            case 3: case 4: scale = 4; break;
            case 5: scale = 3; break;
            case 6: scale = 2; break;
            default: scale = 0; break;
        }
        return k * scale;
    }

    __device__
    metadata operator>>(uint32_t shift_amount) const {
        metadata out;

        if (shift_amount < limb_bits) {
            out.data[0] = (data[0] >> shift_amount) | (data[1] << (limb_bits - shift_amount));
            out.data[1] = data[1] >> shift_amount;
        } else if (shift_amount < bits) {
            out.data[0] = data[1] >> (shift_amount - limb_bits);
            out.data[1] = 0;
        } else {
            out.data[1] = out.data[0] = 0;
        }

        return out;
    }

    __device__
    metadata operator<<(uint32_t shift_amount) const {
        metadata out;

        if (shift_amount < limb_bits) {
            out.data[1] = (data[1] << shift_amount) | (data[0] >> (limb_bits - shift_amount));
            out.data[0] = data[0] << shift_amount;
        } else if (shift_amount < bits) {
            out.data[1] = data[0] << (shift_amount - limb_bits);
            out.data[0] = 0;
        } else {
            out.data[1] = out.data[0] = 0;
        }

        return out;
    }
};

// The `table_data_ptr` struct is designed to hold pointers to data structures.
struct table_data_ptr {
    uint2* ys;
    uint2* matches;
};

// The `Table` class is designed to manage and store data structures used in the table creation process.
//
// # Member Variables
// - `size_t size`: Holds the number of elements in the table.
// - `bool metadata_exists`: Indicates whether metadata is present.
// - `ys`: `uint2` type data on the GPU, which holds the sorted `y` values and their original indices.
// - `matches`: `uint2` type match data on the GPU (allocated if metadata is required).
// - `y`: `uint32_t` type data on the GPU.
// - `metadatas`: `metadata` type data on the GPU (allocated if metadata is required).
class Table {
public:
    size_t size = 0;
    bool metadata_exists = false;
    uint2* ys;
    uint2* matches;
    uint32_t* y;
    metadata* metadatas;

    Table() = default;

    Table(const gpu_t& gpu, size_t init_size, bool metadata_required)
        : size(init_size), metadata_exists(metadata_required),
          ys((uint2*)gpu.Dmalloc(init_size * sizeof(uint2))),
          matches(metadata_required ?
                  (uint2*)gpu.Dmalloc(init_size * sizeof(uint2)) : nullptr),
          y((uint32_t*)gpu.Dmalloc(init_size * sizeof(uint32_t))),
          metadatas(metadata_required ?
                    (metadata*)gpu.Dmalloc(init_size * sizeof(metadata)) : nullptr) {}

    void free_mem(const gpu_t& gpu)
    {
        gpu.Dfree(ys);
        gpu.Dfree(matches);
        gpu.Dfree(y);
        gpu.Dfree(metadatas);
    }

    table_data_ptr get_table_data() const
    {
        table_data_ptr data;
        data.ys = &ys[0];
        data.matches = &matches[0];
        return data;
    }
};

// Manages and initializes data structures specific to a single GPU.
class gpu_specific_state {
public:
    const gpu_t& gpu;
    uint64_t* proof;
    Table tables[NUM_TABLES];
    uint32_t* challenge_index;
    uint2* temp_sort;
    uint2* histogram;
    chacha_state* out_chacha;
    bool initialized = false;
    uint32_t current_K = 0;
    uint32_t current_challenges_count = 0;
    std::unique_ptr<std::mutex> mtx;

    gpu_specific_state(int id) : gpu(select_gpu(id)), mtx(std::make_unique<std::mutex>()) {}

    // Initializes GPU-specific data structures.
    // K: An unsigned 32-bit integer that determines the size of certain data structures.
    // challenges_count: Number of challenges to use that determines the size of certain data structures.
    void initialize_data(uint32_t K, uint32_t challenges_count)
    {
        // Checks if the GPU state is already initialized with sufficient sizes for K and challenges_count.
        // If the current_K and current_challenges_count are greater than or equal to the new values,
        // it means the GPU state is already properly initialized and no reallocation is needed.
        if (initialized && current_K >= K && current_challenges_count >= challenges_count)
            return;

        // Frees any previously allocated memory
        free_mem();

        // Calculates the maximum table size based on K.
        uint32_t max_table_size = 2 * (1 << K);

        // Initializes the first table with `max_table_size`.
        tables[0] = Table(gpu, max_table_size, false);
        // Initializes the remaining tables.
        for (size_t i = 1; i < NUM_TABLES; i++) {
            tables[i] = Table(gpu, max_table_size, true);
        }

        // Calculates the maximum proof size. Allocates GPU memory for proofs and challenge indices.
        uint32_t max_proof_size = challenges_count * K;
        proof = (uint64_t*)gpu.Dmalloc(max_proof_size * sizeof(uint64_t));
        challenge_index = (uint32_t*)gpu.Dmalloc(challenges_count * sizeof(uint32_t));

        // Allocates GPU memory for temporary sorting buffer.
        temp_sort = (uint2*)gpu.Dmalloc(max_table_size * sizeof(uint2));

        // Calculates the histogram size and allocates GPU memory for histogram.
        uint32_t y_bit_size = K + PARAM_EXT;
        size_t histogram_size = (((size_t)1 << y_bit_size) + PARAM_BC - 1) / PARAM_BC;
        histogram = (uint2*)gpu.Dmalloc(histogram_size * sizeof(uint2));

        // Calculates the output length in bytes and allocates GPU memory for ChaCha states.
        size_t output_len_bytes = K * ((size_t)1 << K) / 8;
        out_chacha = (chacha_state*)gpu.Dmalloc(output_len_bytes * sizeof(chacha_state));

        initialized = true;
        current_K = K;
        current_challenges_count = challenges_count;
    }

    void free_mem()
    {
        if (!initialized)
            return;

        for (size_t i = 0; i < NUM_TABLES; i++) {
            tables[i].free_mem(gpu);
        }

        gpu.Dfree(proof);
        gpu.Dfree(challenge_index);
        gpu.Dfree(temp_sort);
        gpu.Dfree(histogram);
        gpu.Dfree(out_chacha);

        initialized = false;
    }
};

// Manages multiple gpu_specific_state instances,
// ensuring proper GPU resource allocation and synchronization.
class subspace_proof_state {
public:
    subspace_proof_state(subspace_proof_state const&) = delete;
    void operator=(subspace_proof_state const&) = delete;

    std::vector<gpu_specific_state> gpu_specific_states;

    subspace_proof_state()
    {
        int num_gpus = ngpus();
        gpu_specific_states.reserve(num_gpus);
        for (size_t id = 0; id < ngpus(); id++) {
            gpu_specific_states.emplace_back((int)id);
        }
    }

    static subspace_proof_state& get_proof_state()
    {
        static subspace_proof_state proof_state;
        return proof_state;
    }
};

static subspace_proof_state& proof_state = subspace_proof_state::get_proof_state();
