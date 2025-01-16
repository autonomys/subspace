// Originally written by Supranational LLC

__device__ __forceinline__
uint32_t byte_swap(uint32_t in)
{
    return ((in >> 24) & 0x000000FF) |
           ((in >> 8) & 0x0000FF00) |
           ((in << 8) & 0x00FF0000) |
           ((in << 24) & 0xFF000000);
}

template <typename T>
__device__ __forceinline__
T endianness_swap(const T& in)
{
    T out;

    #pragma unroll
    for (uint32_t i = 0; i < out.len(); i++)
        out[out.len() - i - 1] = byte_swap(in[i]);

    return out;
}

template <typename T>
__global__ __launch_bounds__(1024)
void kern_endianness_swap(T* out, const T* in, size_t size)
{
    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;

    for (size_t i = tid; i < size; i += (size_t)gridDim.x * blockDim.x) {
        T temp = in[i];
        temp = endianness_swap(temp);
        out[i] = temp;
    }
}

template <typename T>
__global__ __launch_bounds__(1024)
void convert_to_mont(T* out, const T* in, size_t size)
{
    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;

    for (size_t i = tid; i < size; i += (size_t)gridDim.x * blockDim.x) {
        T temp = in[i];
        temp.to();
        out[i] = temp;
    }
}
