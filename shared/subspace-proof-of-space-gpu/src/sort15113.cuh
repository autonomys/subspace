// Originally written by Supranational LLC

#ifndef __SUBSPACE_SORT_CUH__
#define __SUBSPACE_SORT_CUH__
#include <cstdint>
#include <cassert>
#include <util/vec2d_t.hpp>

/*
 * Custom sorting, we take in values in [0, 2**|bits|) range and return
 * their indices and the least significant digit base 15113.
 * Histogram contains initial indices and amount of elements that share
 * the same most significant digit.
 */

#define SORT_BLOCKDIM 1024

#define RADIX 15113
#define DIGIT_BITS 14   // 15113 is a 14-bit number.

#ifndef WARP_SZ
# define WARP_SZ 32
#endif
#ifdef __GNUC__
# define asm __asm__ __volatile__
#else
# define asm asm volatile
#endif

static const uint32_t N_COUNTERS = 1<<DIGIT_BITS;
static const uint32_t N_SUMS = N_COUNTERS / SORT_BLOCKDIM;
extern __shared__ uint32_t counters[];

__device__ __forceinline__
uint32_t sum_up(uint32_t sum, const uint32_t limit = WARP_SZ)
{
    #pragma unroll
    for (uint32_t off = 1; off < limit; off <<= 1) {
#if defined(__CUDACC__)
        asm("{ .reg.b32 %v; .reg.pred %did;"
            "  shfl.sync.up.b32 %v|%did, %0, %1, 0, 0xffffffff;"
            "  @%did add.u32 %0, %0, %v;"
            "}" : "+r"(sum) : "r"(off));
#elif defined(__HIPCC__)
        uint32_t idx = threadIdx.x - off;
        uint32_t val = __builtin_amdgcn_ds_bpermute(idx<<2, sum);
        if (threadIdx.x % WARP_SZ >= off)
            sum += val;
#else
# error "unsupported platform"
#endif
    }

    return sum;
}

__device__ __forceinline__
void zero_counters()
{
    #pragma unroll
    for (uint32_t i = 0; i < N_SUMS/4; i++)
        ((uint4*)counters)[threadIdx.x + i*SORT_BLOCKDIM] = uint4{0, 0, 0, 0};
    __syncthreads();
}

__device__ __forceinline__
void count_digits(const uint32_t src[], uint32_t base, uint32_t len)
{
    zero_counters();

    src += base;
    // count occurrences of each non-zero digit
    for (uint32_t i = threadIdx.x; i < len; i += SORT_BLOCKDIM) {
        auto val = src[(size_t)i];
        (void)atomicAdd(&counters[val / RADIX], 1);
    }

    __syncthreads();
}

__device__ __forceinline__
void scatter(uint2 dst[], const uint32_t src[], uint32_t base, uint32_t len)
{
    src += base;
    #pragma unroll 1    // the subroutine is memory-io-bound, unrolling makes no difference
    for (uint32_t i = threadIdx.x; i < len; i += SORT_BLOCKDIM) {
        auto val = src[(size_t)i];
        auto hi = val / RADIX;
        auto lo = val - hi * RADIX; // val % RADIX
        uint32_t idx = atomicSub(&counters[hi], 1) - 1;
        dst[idx] = uint2{base+i, lo};
    }
}

__device__ __forceinline__
static void upper_sort(uint2 dst[], const uint32_t src[], uint32_t len,
                       uint2 histogram[], uint32_t upper_digits,
                       bool as_kernel = false)
{
    uint32_t grid_div = 31 - __clz(min(gridDim.x, WARP_SZ));
    uint32_t grid_rem = (1<<grid_div) - 1;
    uint32_t grid_dim = 1<<grid_div;

    uint32_t slice = len >> grid_div;   // / gridDim.x;
    uint32_t rem   = len & grid_rem;    // % gridDim.x;
    uint32_t base;

    // borrow |dst| to collect counters from SMs
    vec2d_t<uint32_t> htemp{reinterpret_cast<uint32_t*>(dst), grid_dim};

    if (as_kernel || blockIdx.x < grid_dim) {
        if (blockIdx.x < rem)
            base = ++slice * blockIdx.x;
        else
            base = slice * blockIdx.x + rem;

        count_digits(src, base, slice);

        #pragma unroll 1
        for (uint32_t i = threadIdx.x; i < upper_digits; i += SORT_BLOCKDIM)
            htemp[i][blockIdx.x] = counters[i];
    }

    cooperative_groups::this_grid().sync();
    __syncthreads();    // eliminate BRA.DIV?

    uint32_t carry_sum, lane_off;

    if (as_kernel || blockIdx.x < grid_dim) {
        const uint32_t warpid = threadIdx.x / WARP_SZ;
        const uint32_t laneid = threadIdx.x % WARP_SZ;
        const uint32_t sub_warpid = laneid >> grid_div; // / gridDim.x;
        const uint32_t sub_laneid = laneid & grid_rem;  // % gridDim.x;
        const uint32_t stride = WARP_SZ >> grid_div;    // / gridDim.x;

        uint2 h = uint2{0, 0};
        uint32_t sum, warp_off = warpid*WARP_SZ*N_SUMS + sub_warpid;

        #pragma unroll 1
        for (uint32_t i = 0; i < WARP_SZ*N_SUMS; i += stride, warp_off += stride) {
            sum = (warp_off < upper_digits) ? htemp[warp_off][sub_laneid] : 0;
            sum = sum_up(sum) + h.x;

            if (sub_laneid == blockIdx.x)
                counters[warp_off] = sum;

#if defined(__CUDACC__)
            asm("{ .reg.b32 %v; .reg.pred %did;");
            asm("shfl.sync.up.b32 %v|%did, %0, 1, 0, 0xffffffff;" :: "r"(sum));
            asm("@%did mov.b32 %0, %v;" : "+r"(h.x));
            asm("}");
            h.y = __shfl_down_sync(0xffffffff, sum, grid_dim-1) - h.x;
#elif defined(__HIPCC__)
            uint32_t idx = threadIdx.x - 1;
            uint32_t tmp = __builtin_amdgcn_ds_bpermute(idx<<2, sum);
            if (threadIdx.x % WARP_SZ >= 1)
                h.x = tmp;

            idx = threadIdx.x + grid_dim-1;
            h.y = __builtin_amdgcn_ds_bpermute(idx<<2, sum) - h.x;
#else
# error "unsupported platform"
#endif

            if (blockIdx.x == 0 && sub_laneid == 0 && warp_off < upper_digits)
                histogram[warp_off] = h;

            h.x = __shfl_sync(0xffffffff, sum, WARP_SZ-1, WARP_SZ);
        }

        if (warpid == 0)    // offload some counters to registers
            sum = counters[laneid];

        __syncthreads();

        // carry over most significant prefix sums from each warp
        if (laneid == WARP_SZ-1)
            counters[warpid] = h.x;

        __syncthreads();

        carry_sum = laneid ? counters[laneid-1] : 0;

        __syncthreads();

        if (warpid == 0)    // restore offloaded counters
            counters[laneid] = sum;

        __syncthreads();

        carry_sum = sum_up(carry_sum, SORT_BLOCKDIM/WARP_SZ);
        carry_sum = __shfl_sync(0xffffffff, carry_sum, warpid);

        lane_off = warpid*WARP_SZ*N_SUMS + laneid;

        #pragma unroll
        for (uint32_t i = 0; i < N_SUMS; i++)
            (void)atomicAdd(&counters[lane_off + i*WARP_SZ], carry_sum);
    }

    cooperative_groups::this_grid().sync();
    __syncthreads();

    if (as_kernel || blockIdx.x < grid_dim) {
        scatter(dst, src, base, slice);

        if (blockIdx.x == 0) {
            #pragma unroll 1
            for (uint32_t i = 0; i < N_SUMS; i++, lane_off += WARP_SZ)
                if (lane_off < upper_digits)
                    (void)atomicAdd(&histogram[lane_off].x, carry_sum);
        }
    }

    if (!as_kernel) {
        cooperative_groups::this_grid().sync();
        __syncthreads();
    }
}

__device__ __forceinline__
uint2 count_digits(const uint2 src[], uint32_t len)
{
    zero_counters();

    uint2 first;
    uint32_t i = threadIdx.x;

    // count occurrences of each digit
    if (i < len) {
        first = src[i];
        (void)atomicAdd(&counters[first.y], 1);
    }

    for (i += SORT_BLOCKDIM; i < len; i += SORT_BLOCKDIM)
        (void)atomicAdd(&counters[src[i].y], 1);

    __syncthreads();

    return first;
}

__device__ __forceinline__
void scatter(uint2 dst[], const uint2 src[], uint32_t len, uint2 first,
             uint32_t hi_digit)
{
    uint32_t i = threadIdx.x;

    if (i < len) {
        uint32_t idx = atomicSub(&counters[first.y], 1) - 1;
        first.y += hi_digit * RADIX;
        dst[idx] = first;
    }

    #pragma unroll 1    // the subroutine is memory-io-bound, unrolling makes no difference
    for (i += SORT_BLOCKDIM; i < len; i += SORT_BLOCKDIM) {
        auto val = src[(size_t)i];
        uint32_t idx = atomicSub(&counters[val.y], 1) - 1;
        val.y += hi_digit * RADIX;
        dst[idx] = val;
    }
}

__device__ __forceinline__
static void lower_sort(uint2 dst[], const uint2 src[], uint32_t base,
                       uint32_t len, uint32_t hi_digit)
{
    auto first = count_digits(src += base, len);

    const uint32_t warpid = threadIdx.x / WARP_SZ;
    const uint32_t laneid = threadIdx.x % WARP_SZ;

    uint32_t prefix_sums[N_SUMS];
    uint32_t lane_off = warpid*WARP_SZ*N_SUMS + laneid;

    // calculate per-warp prefix sums
    #pragma unroll
    for (uint32_t i = 0; i < N_SUMS; i++) {
        uint32_t off = lane_off + i*WARP_SZ;
        uint32_t sum = counters[off];

        sum = sum_up(sum);
        if (i > 0)
            sum += __shfl_sync(0xffffffff, prefix_sums[i-1], WARP_SZ-1);

        prefix_sums[i] = sum;
    }

    // carry over most significant prefix sums from each warp
    if (laneid == WARP_SZ-1)
        counters[warpid*(WARP_SZ*N_SUMS+1)] = prefix_sums[N_SUMS-1];

    __syncthreads();

    uint32_t carry_sum = laneid ? counters[(laneid-1)*(WARP_SZ*N_SUMS+1)] : 0;

    __syncthreads();

    carry_sum = sum_up(carry_sum, SORT_BLOCKDIM/WARP_SZ);
    carry_sum = __shfl_sync(0xffffffff, carry_sum, warpid);
    carry_sum += base;

    #pragma unroll
    for (uint32_t i = 0; i < N_SUMS; i++)
        counters[lane_off + i*WARP_SZ] = prefix_sums[i] += carry_sum;

    __syncthreads();

    scatter(dst, src, len, first, hi_digit);

    __syncthreads();
}

__device__ __forceinline__
void sort_device(uint2 out[], const uint32_t in[], uint32_t len, uint2 temp[],
                 uint2 histogram[], bool emit_original_value, int bits = 2*DIGIT_BITS)
{
    uint32_t upper_digits = ((1<<bits) + RADIX - 1) / RADIX;
    uint32_t grid_div = 31 - __clz(min(gridDim.x, WARP_SZ));

    assert(bits <= 2*DIGIT_BITS && bits > DIGIT_BITS &&
           (upper_digits<<grid_div)/2 <= len);

    upper_sort(temp, in, len, histogram, upper_digits);

    #pragma unroll 1
    for (size_t i = blockIdx.x; i < upper_digits; i += gridDim.x)
        lower_sort(out, temp, histogram[i].x, histogram[i].y, emit_original_value ? i : 0);
}

__launch_bounds__(SORT_BLOCKDIM)
__global__ void sort15113(uint2 out[], const uint32_t in[],
                          const uint32_t* match_counter, uint2 temp[],
                          uint2 histogram[], bool emit_original_value, int bits = 2*DIGIT_BITS)
{
    uint32_t len = *match_counter;
    sort_device(out, in, len, temp, histogram, emit_original_value, bits);
}

__launch_bounds__(SORT_BLOCKDIM)
__global__ void sort15113(uint2 out[], const uint32_t in[], uint32_t len, uint2 temp[],
                          uint2 histogram[], bool emit_original_value, int bits = 2*DIGIT_BITS)
{
    sort_device(out, in, len, temp, histogram, emit_original_value, bits);
}

# undef asm
#endif
