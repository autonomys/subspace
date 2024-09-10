# Subspace proof of space implementation for GPU (low-level proving utilities)

This crate exposes some low-level primitives to accelerate proof of space implementation on Nvidia (CUDA, Volta+) and
AMD (ROCm) GPUs.

## Build requirements

### CUDA
For Nvidia support CUDA toolkit needs to be installed, which can be done on Ubuntu 24.04 like this:
```bash
sudo apt-get install nvidia-cuda-toolkit
```

In case you have newer GCC installed, you may need to install `g++-12` and set it as a C++ compiler of choice during
compilation, something like this:
```bash
CXX=g++-12 cargo build
```

For other operating systems/platforms check official documentation: <https://docs.nvidia.com/cuda/>

### ROCm

For AMD/ROCm support follow their official documentation: <https://rocm.docs.amd.com/en/latest/>
