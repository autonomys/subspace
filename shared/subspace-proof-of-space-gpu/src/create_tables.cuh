// Originally written by Supranational LLC

template<int K, int PARAM_EXT>
__global__ __launch_bounds__(1024)
void compute_fn(uint32_t* out_y, metadata* out_metadata,
                const uint2* y_sorted, const uint32_t* in_y,
                const uint2* matches, const uint32_t* match_counter,
                const metadata* in_metadata, int table_number)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;

    uint32_t N = *match_counter;
    for (uint32_t i = tid; i < N; i += gridDim.x * blockDim.x) {
        // Determine x_index and y_index based on previous y index
        uint32_t x_index = y_sorted[matches[i].x].x;
        uint32_t y_index = y_sorted[matches[i].y].x;

        // Initialize metadata structures
        metadata left_metadata = {0};
        metadata right_metadata = {0};

        // Set left_metadata and right_metadata based on table_number
        if (table_number == 2) {
            // For table_number 2, directly set metadata from indices
            // because there is no metadata table created for table_number 1
            // and table1 always has a length of 1 << K,
            // hence metadata is selected based on the previous y index values.
            left_metadata.data[0] = x_index;
            right_metadata.data[0] = y_index;
        } else {
            // For other table numbers, retrieve metadata from input metadata array
            left_metadata = in_metadata[x_index];
            right_metadata = in_metadata[y_index];
        }

        uint32_t parent_metadata_bits = metadata::size_bits(K, table_number - 1);

        // Take only bytes where bits were set
        uint32_t num_bytes_with_data
            = ((K + PARAM_EXT) + (2 * parent_metadata_bits) + 7) / 8;

        // Move bits of `left_metadata` at the final offset of eventual `input_a`
        metadata input_a;
        input_a = left_metadata << (metadata::bits - parent_metadata_bits - (K + PARAM_EXT));

        // Collect `K + PARAM_EXT` most significant bits of `y` at the final offset of eventual `input_a`
        input_a.data[1] |= (uint64_t)in_y[y_sorted[matches[i].x].x] << (64 - (K + PARAM_EXT));

        // Part of the `right_bits` at the final offset of eventual `input_a`
        uint32_t y_and_left_bits = (K + PARAM_EXT) + parent_metadata_bits;
        uint32_t right_bits_start_offset = metadata::bits - parent_metadata_bits;

        // Initialize the input array for BLAKE3 hash function
        // Initialize block length for BLAKE3 compression
        uint64_t blake_input[8] = {0};
        uint32_t block_len;

        // If `right_metadata` bits start to the left of the desired position in `input_a` move
        // bits right, else move left
        if (right_bits_start_offset < y_and_left_bits) {
            uint32_t right_bits_pushed_into_input_b = y_and_left_bits -
                                                      right_bits_start_offset;

            // Collect bits of `right_metadata` that will fit into `input_a` at the final offset in
            // eventual `input_a`
            metadata right_bits_shifted;
            right_bits_shifted = right_metadata >> right_bits_pushed_into_input_b;
            for (uint32_t j = 0; j < 2; j++) {
                input_a.data[j] |= right_bits_shifted.data[j];
            }

            // Collect bits of `right_metadata` that will spill over into `input_b`
            metadata input_b;
            input_b = right_metadata << metadata::bits - right_bits_pushed_into_input_b;

            // Prepare input for BLAKE3 hash function by performing a byte swap
            input_a.byte_swap(blake_input);
            input_b.byte_swap(&blake_input[metadata::bits / 64]);

            // Calculate the total block length for BLAKE3 compression
            // This includes the bytes from input_b and the metadata bits from input_a
            uint32_t input_b_bytes_count = (right_bits_pushed_into_input_b + 7) / 8;
            block_len = input_b_bytes_count + (metadata::bits / 8);
        } else {
            uint32_t right_bits_pushed_into_input_b = right_bits_start_offset -
                                                      y_and_left_bits;

            metadata right_bits_shifted;
            right_bits_shifted = right_metadata << right_bits_pushed_into_input_b;

            for (uint32_t j = 0; j < 2; j++) {
                input_a.data[j] |= right_bits_shifted.data[j];
            }

            input_a.byte_swap(blake_input);
            block_len = num_bytes_with_data;
        }
        // Initialize the BLAKE3 state with the given chaining value and block length
        // Perform BLAKE3 compression on the prepared input data
        blake3_state state = initialize_blake3_state(block_len);
        blake3_compress(state, (uint8_t*)blake_input);

        // Retrieve the first 32-bit word of the BLAKE3 hash state
        // Apply a byte swap operation to convert the hash to little-endian format
        // Extract the highest K + PARAM_EXT bits from the little-endian hash to compute y values.
        uint32_t hash = state.data[0];
        uint32_t little_endian_hash = byte_swap(hash);
        out_y[i] =  little_endian_hash >> (32 - (K + PARAM_EXT));

        // Perform metadata computation
        uint32_t metadata_bits = metadata::size_bits(K, table_number);
        if (table_number < 4) {
            left_metadata = left_metadata << parent_metadata_bits;
            for (uint32_t j = 0; j < 2; j++) {
                left_metadata.data[j] = left_metadata.data[j] | right_metadata.data[j];
            }
            out_metadata[i] = left_metadata;
        } else if (metadata_bits > 0) {
            // For K under 25 it is guaranteed that metadata + bit offset will always fit into u128.
            // We collect bytes necessary, potentially with extra bits at the start and end of the bytes
            // that will be taken care of later.
            uint8_t* hash_bytes = reinterpret_cast<uint8_t*>(state.data);
            uint32_t start_index = (K + PARAM_EXT) / 8;
            metadata raw_meta;
            for (uint32_t j = 0; j < 16; j++) {
                reinterpret_cast<uint8_t*>(raw_meta.data)[15 - j]
                    = hash_bytes[j + start_index];
            }
            // Remove extra bits at the beginning
            left_metadata = raw_meta << ((K + PARAM_EXT) % 8);
            // Move bits into correct location
            left_metadata = left_metadata >> (metadata::bits - metadata_bits);
            out_metadata[i] = left_metadata;
        }
    }
}

template<int K, int PARAM_EXT>
__global__ __launch_bounds__(1024)
void compute_f1(uint32_t* output, uint32_t* input, size_t N)
{
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;

    uint32_t mask = (1 << PARAM_EXT) - 1;
    for (size_t i = tid; i < N; i += gridDim.x * blockDim.x) {
        size_t bit_off = i * K;

        union {
            uint64_t ul;
            uint32_t u[2];
        };

        // Load 32-bit chunks from input array and perform byte swap
        u[0] = byte_swap(input[bit_off / 32 + ((bit_off % 32 + K) >= 32)]);
        u[1] = byte_swap(input[bit_off / 32]);

        // Extract K bits starting from bit_off position
        uint32_t y_bytes = (uint32_t)((ul << (bit_off % 32)) >> 32);
        y_bytes = y_bytes >> (32 - K);

        // Apply masks and combine
        output[i] = ((y_bytes << PARAM_EXT) & ~mask) | ((i >> (K - PARAM_EXT)) & mask);
    }
}
