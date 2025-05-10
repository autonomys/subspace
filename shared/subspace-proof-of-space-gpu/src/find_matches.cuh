// Originally written by Supranational LLC

__device__ __forceinline__
uint32_t calculate_destination(uint32_t parity, uint32_t r, uint32_t m)
{
    uint32_t dest = ((r / PARAM_C + m) % PARAM_B) * PARAM_C
                  + (((2 * m + parity) * (2 * m + parity) + r) % PARAM_C);

    return dest;
}

// If a matching value is found, return the index of the leftmost occurence
// of the value in "data" (in case there are duplicates)
// If a matching value is not found, return the index of the value which is
// closest to but still smaller than dest
__device__ __forceinline__
uint32_t binary_search(const uint32_t* data, uint32_t num_elems, uint32_t dest)
{
    uint32_t left = 0, right = num_elems;

    while (left < right) {
        uint32_t middle = (left + right) / 2;

        if (data[middle] < dest)
            left = middle + 1;
        else
            right = middle;
    }

    return left;
}

// One block (of 256 threads) goes over a pair of buckets
static const uint32_t block_sz = 256;

__global__ __launch_bounds__(1024)
void find_matches(uint2* out, const uint2* ys, const uint2* histogram,
                  uint32_t* global_match_count)
{
    // This constant is based on the likely number of elements in each bucket. Generally it will not exceed 512, which
    // means a single call will process the bucket. When it does exceed 512 the remaining elements are processed in the
    // next pass. This is a heuristic and not expected to impact performance significantly either way.
    const uint32_t right_bucket_step = 512;
    const uint32_t warp_count = block_sz / WARP_SZ;
    const uint32_t warp_match_threshold = 4 * WARP_SZ;
    const uint32_t warp_partition_size = warp_match_threshold + 2 * WARP_SZ;

    extern __shared__ uint2 scratchpad[];

    uint32_t warpid = threadIdx.x / WARP_SZ;
    uint32_t laneid = threadIdx.x % WARP_SZ;

    // Each warp has its own partition in shared memory to write the matches into
    // to avoid shared memory atomic operations
    uint2* matches = &scratchpad[warpid * warp_partition_size];
    uint32_t* shr_right_ys = (uint32_t*)&scratchpad[warp_count * warp_partition_size];

    uint32_t left_bucket_idx = blockIdx.x;

    uint32_t left_bucket_start  = histogram[left_bucket_idx].x;
    uint32_t left_bucket_size   = histogram[left_bucket_idx].y;
    uint32_t right_bucket_start = histogram[left_bucket_idx + 1].x;
    uint32_t right_bucket_size  = histogram[left_bucket_idx + 1].y;

    uint32_t left_upper_bound = ((left_bucket_size + WARP_SZ - 1) / WARP_SZ) * WARP_SZ;

    const uint2* left_ys  = &ys[left_bucket_start];
    const uint2* right_ys = &ys[right_bucket_start];

    uint32_t warp_match_count = 0;

    // We iterate over the right bucket in 512-element chunks
    for (uint32_t right_iter = 0; right_iter < right_bucket_size; right_iter += right_bucket_step) {
        uint32_t current_right_size = min(right_bucket_size - right_iter,
                                          right_bucket_step);

        // Read the next chunks of right bucket y elements into shared memory
        #pragma unroll
        for (uint32_t i = 0; i < right_bucket_step / block_sz; i++) {
            uint32_t off = threadIdx.x + i * block_sz;
            shr_right_ys[threadIdx.x + i * block_sz] =
                off < current_right_size ? right_ys[right_iter + off].y
                                         : 0xFFFFFFFF;
        }

        __syncthreads();

        // The largest y value in the current chunk of right bucket y elements
        uint32_t last_right_y = shr_right_ys[current_right_size - 1];

        // Each thread reads a y value from the left bucket
        // Each thread will calculate all PARAM_M (64) "dest" values and
        // check for matches
        for (uint32_t left_iter = threadIdx.x; left_iter < left_upper_bound; left_iter += block_sz) {
            // All the threads in a warp must execute this loop, but if
            // a y value is not left for a thread, then they obtain an invalid
            // left y value so that they will not find any matches
            uint32_t participate = left_iter < left_bucket_size;
            uint32_t left_y = participate ? left_ys[left_iter].y : 0xFFFFFFFF;
            uint32_t left_idx = participate ? left_bucket_start + left_iter : 0;

            // Calculate the first "dest" value and perform a binary search
            // even if there isn't an exact find, we obtain the index of the
            // right y value which is the closest to (but still smaller than)
            // the dest value
            uint32_t dest = calculate_destination(left_bucket_idx % 2, left_y, 0);
            uint32_t shr_right_y_idx = binary_search(shr_right_ys, current_right_size, dest);
            uint32_t right_y = shr_right_ys[shr_right_y_idx];

            // We loop through the rest of the "dest" values
            // "dest" values are ascending modulo 15113. We will use this
            // property to quickly find the closest (or matching) right y index
            // as we loop through consecutive "dest" values
            #pragma unroll 8
            for (uint32_t m = 0; m < PARAM_M; m++) {
                uint32_t prev_dest = dest;
                dest = calculate_destination(left_bucket_idx % 2, left_y, m);

                // If the next "dest" value wraps around 15113, the right y
                // index must also wrap back to the start
                if (dest < prev_dest) {
                    shr_right_y_idx = 0;
                    right_y = shr_right_ys[shr_right_y_idx];
                }

                // Quickly find the closest (or matching) index of a right y
                // for the next "dest" value
                if (dest <= last_right_y) {
                    while (right_y < dest) {
                        shr_right_y_idx++;
                        right_y = shr_right_ys[shr_right_y_idx];
                    }
                }

                uint32_t current_match_count;
                uint32_t wrap_around = 1;

                do {
                    uint32_t is_a_match = dest == right_y && participate && wrap_around;

                    // A bitmap where the "i"th bit is 1 if the thread with lane
                    // "i" has found a match
                    uint64_t mask = __ballot_sync(0xFFFFFFFF, is_a_match);

                    // Summing up the number of set bits, we get the number of
                    // matches in the warp
                    current_match_count = __popc(mask);
                    // Each thread computes a unique write index into shared memory
                    mask <<= WARP_SZ - laneid;
                    uint32_t off = __popc(mask);

                    // We store the true left and right indices of the match
                    if (is_a_match) {
                        uint32_t right_idx = right_bucket_start + right_iter + shr_right_y_idx;
                        matches[warp_match_count + off] = uint2{left_idx, right_idx};
                    }

                    // Increment the right index and re-check for matches, to
                    // account for any duplicate values
                    shr_right_y_idx += is_a_match;
                    // If the entirety of the current chunk of right y values
                    // consists of only one value (or some duplicates of it),
                    // we stop matching after we wrap around the right y chunk
                    wrap_around = shr_right_y_idx < current_right_size;
                    shr_right_y_idx *= wrap_around;

                    right_y = shr_right_ys[shr_right_y_idx];

                    warp_match_count += current_match_count;
                    // Loop until all threads in a warp have exhausted the duplicates
                } while (current_match_count);
            }

            // Each warp checks whether their partition in shared memory
            // is sufficiently full. If it is, we write the matches into
            // global memory and reset the shared partition for the warp
            if (warp_match_count > warp_match_threshold) {
                uint32_t global_off = 0;
                if (laneid == 0)
                    global_off = atomicAdd(global_match_count, warp_match_count);

                global_off = __shfl_sync(0xFFFFFFFF, global_off, 0);

                for (uint32_t i = laneid; i < warp_match_count; i += WARP_SZ)
                    out[global_off + i] = matches[i];

                warp_match_count = 0;
            }
        }
    }

    // Write any matches into global memory
    uint32_t global_off = 0;
    if (laneid == 0)
        global_off = atomicAdd(global_match_count, warp_match_count);

    global_off = __shfl_sync(0xFFFFFFFF, global_off, 0);

    for (uint32_t i = laneid; i < warp_match_count; i += WARP_SZ)
        out[global_off + i] = matches[i];
}
