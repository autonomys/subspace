// Originally written by Supranational LLC

#include <cstdint>
#include <cassert>

// Define constants used for BLAKE3 operation.
static const int CHUNK_START = 1 << 0;
static const int CHUNK_END = 1 << 1;
static const int ROOT = 1 << 3;
static const int BLOCK_LEN = 64;

__device__ __constant__
const uint32_t IV[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

struct __align__(16) blake3_state {
    uint32_t data[16];
};

// Convert a 64-byte block into 16 uint32_t words for processing.
static __device__ __forceinline__
void bytes_to_words(const uint8_t bytes[64], uint32_t words[16])
{
    for (int i = 0; i < 16; i++) {
        words[i] = reinterpret_cast<const uint32_t*>(bytes)[i];
    }
}

static __device__ __forceinline__
blake3_state initialize_blake3_state(const uint32_t block_len,
                                     const uint32_t chaining_value[8] = IV,
                                     uint32_t flag = (CHUNK_START + CHUNK_END) + ROOT,
                                     const uint64_t counter = 0)
{
    blake3_state state;

    // Setup the chaining values from the input or previous state.
    for (int i = 0; i < 8; i++) {
        state.data[i] = chaining_value[i];
    }

    // Setup the initial state values from the IV.
    for (int i = 0; i < 4; i++) {
        state.data[8 + i] = IV[i];
    }

    // Counter, block length and flag setup for different hash states.
    state.data[12] = static_cast<uint32_t>(counter);
    state.data[13] = static_cast<uint32_t>(counter >> 32);
    state.data[14] = block_len;
    state.data[15] = flag;

    return state;
}

// Permute the message block according to BLAKE3's specification.
static __device__ __forceinline__
void permute(uint32_t out[16], const uint32_t in[16])
{
    static const int MSG_PERMUTATION[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12,
                                            5, 9, 14, 15, 8};
    for (int i = 0; i < 16; ++i) {
        out[i] = in[MSG_PERMUTATION[i]];
    }
}

// BLAKE3 quarter round transformation as part of the compress function.
static __device__ __forceinline__
void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                   const uint32_t mx, const uint32_t my)
{
    a += b + mx;
    d ^= a;
    d = (d << 16) | (d >> 16);

    c += d;
    b ^= c;
    b = (b << 20) | (b >> 12);

    a += b + my;
    d ^= a;
    d = (d << 24) | (d >> 8);

    c += d;
    b ^= c;
    b = (b << 25) | (b >> 7);
}

// The BLAKE3 compress function that performs the rounds of mixing input data.
static __device__ __forceinline__
void round(blake3_state& state, const uint32_t block[16])
{
    // Perform quarter rounds on the state with the given block data.
    quarter_round(state.data[0], state.data[4], state.data[8], state.data[12], block[0], block[1]);
    quarter_round(state.data[1], state.data[5], state.data[9], state.data[13], block[2], block[3]);
    quarter_round(state.data[2], state.data[6], state.data[10], state.data[14], block[4], block[5]);
    quarter_round(state.data[3], state.data[7], state.data[11], state.data[15], block[6], block[7]);
    quarter_round(state.data[0], state.data[5], state.data[10], state.data[15], block[8], block[9]);
    quarter_round(state.data[1], state.data[6], state.data[11], state.data[12], block[10], block[11]);
    quarter_round(state.data[2], state.data[7], state.data[8], state.data[13], block[12], block[13]);
    quarter_round(state.data[3], state.data[4], state.data[9], state.data[14], block[14], block[15]);
}

// Main compress routine that combines state and message data.
static __device__ __forceinline__
void blake3_compress(blake3_state& state, const uint8_t block_bytes[64],
                     const uint32_t chaining_value[8] = IV)
{
    uint32_t block1[16];
    bytes_to_words(block_bytes, block1);

    uint32_t block2[16];
    for (size_t i = 0; i < 3; i++) {
        round(state, block1);
        permute(block2, block1);
        round(state, block2);
        permute(block1, block2);
    }
    round(state, block1);

    // Finalize the compress by combining the state with the chaining values.
    for (size_t i = 0; i < 8; i++) {
        state.data[i] = state.data[i] ^ state.data[i + 8];
        state.data[i + 8] = state.data[i + 8] ^ chaining_value[i];
    }
}

static __device__ __forceinline__
uint32_t start_flag(uint32_t blocks_compressed)
{
    return blocks_compressed == 0 ? CHUNK_START : 0;
}

// If the input bytes are larger than 64 bytes and smaller than 1024 bytes,
// instead of using the compress function directly, we use this function to
// split the input into chunks of up to 64 bytes and process them using the
// compress function.
static __device__ __forceinline__
blake3_state blake3_update(const uint8_t* input_bytes, size_t input_len)
{
    uint32_t blocks_compressed = 0;
    uint32_t chaining_value[8];

    // Initialize chaining_value using IV constant
    for (int i = 0; i < 8; i++) {
        chaining_value[i] = IV[i];
    }

    // Iterate as long as the number of input bytes is greater than 0.
    // In each iteration, process a maximum of 64 bytes.
    blake3_state state;
    for (uint32_t i = 0; i < input_len; i += BLOCK_LEN) {

        // Determine the smaller value between input_len and BLOCK_LEN
        // because a maximum of BLOCK_LEN can be processed.
        uint32_t current_block_len = (BLOCK_LEN < (input_len - i)) ? BLOCK_LEN : (input_len - i);

        // Set the range of the input byte array to be processed.
        uint8_t block[64] = {0};
        for (uint32_t j = 0; j < current_block_len; j++) {
            block[j] = input_bytes[i + j];
        }

        // Determine the flag value based on whether it is the final step
        // and if this is the start of the chunk.
        bool final_step = (current_block_len == (input_len - i));
        uint32_t flag = final_step ? start_flag(blocks_compressed) | CHUNK_END | ROOT: start_flag(blocks_compressed);

        // Update the state, chaining_value, and current_block_len values.
        state = initialize_blake3_state(current_block_len, chaining_value, flag);

        // Apply the compress function based on the determined state and block values
        // and write the values to the state.
        blake3_compress(state, block, chaining_value);

        // Update the chaining_value with the first 8 values of the state computed by compress.
        for (int j = 0; j < 8; j++) {
            chaining_value[j] = state.data[j];
        }

        blocks_compressed += 1;
    }

    return state;
}
