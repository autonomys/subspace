# This Dockerfile supports both native building and cross-compilation to x86-64, aarch64 and riscv64
FROM --platform=$BUILDPLATFORM ubuntu:22.04

ARG RUSTC_VERSION=nightly-2024-12-24
ARG PROFILE=production
ARG RUSTFLAGS
# Incremental compilation here isn't helpful
ENV CARGO_INCREMENTAL=0
ENV PKG_CONFIG_ALLOW_CROSS=true

ARG BUILDARCH
ARG TARGETARCH

WORKDIR /code

RUN \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        protobuf-compiler \
        curl \
        git \
        llvm \
        clang \
        automake \
        libtool \
        pkg-config \
        make

RUN \
    if [ $BUILDARCH != "arm64" ] && [ $TARGETARCH = "arm64" ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          g++-aarch64-linux-gnu \
          gcc-aarch64-linux-gnu \
          libc6-dev-arm64-cross \
    ; fi

RUN \
    if [ $BUILDARCH != "riscv64" ] && [ $TARGETARCH = "riscv64" ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          g++-riscv64-linux-gnu \
          gcc-riscv64-linux-gnu \
          libc6-dev-riscv64-cross \
    ; fi

RUN \
    if [ $BUILDARCH != "amd64" ] && [ $TARGETARCH = "amd64" ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          g++-x86-64-linux-gnu \
          gcc-x86-64-linux-gnu \
          libc6-dev-amd64-cross \
    ; fi

RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUSTC_VERSION && \
    /root/.cargo/bin/rustup target add wasm32-unknown-unknown && \
    /root/.cargo/bin/rustup component add rust-src --toolchain $RUSTC_VERSION

# Up until this line all Rust images in this repo should be the same to share the same layers

# CUDA toolchain, including support for cross-compilation from x86-64 to aarch64, but NOT from aarch64 to x86-64
RUN \
    if [ "$BUILDARCH/$TARGETARCH" = "amd64/amd64" ] || [ "$BUILDARCH/$TARGETARCH" = "amd64/arm64" ] || [ "$BUILDARCH/$TARGETARCH" = "arm64/arm64" ]; then \
      CUDA_ARCH=$(echo $BUILDARCH | sed "s/amd64/x86_64/g") && \
      curl -OL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/$CUDA_ARCH/cuda-keyring_1.1-1_all.deb && \
      dpkg -i cuda-keyring_1.1-1_all.deb && \
      echo "deb [signed-by=/usr/share/keyrings/cuda-archive-keyring.gpg] https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/$CUDA_ARCH/ /" | tee /etc/apt/sources.list.d/cuda-ubuntu2204-$CUDA_ARCH.list && \
      curl -OL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/$CUDA_ARCH/cuda-ubuntu2204.pin && \
      mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600 && \
      apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cuda-minimal-build-12-4 && \
      echo "/usr/local/cuda/lib64" > /etc/ld.so.conf.d/cuda.conf && \
      if [ "$BUILDARCH/$TARGETARCH" = "amd64/arm64" ]; then \
        CUDA_ARCH="cross-linux-aarch64" && \
        echo "deb [signed-by=/usr/share/keyrings/cuda-archive-keyring.gpg] https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/$CUDA_ARCH/ /" | tee /etc/apt/sources.list.d/cuda-ubuntu2204-$CUDA_ARCH.list && \
        curl -OL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/$CUDA_ARCH/cuda-ubuntu2204.pin && \
        mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600-cross-aarch64 && \
        apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cuda-cross-aarch64-12-4 \
      ; fi && \
      ldconfig \
    ; fi

# ROCm is only used on x86-64 since they don't have other packages
ARG ROCM_VERSION=6.2.2
RUN \
    if [ "$BUILDARCH/$TARGETARCH" = "amd64/amd64" ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gpg && \
      mkdir -p --mode=0755 /etc/apt/keyrings && \
      curl -L https://repo.radeon.com/rocm/rocm.gpg.key | gpg --dearmor > /etc/apt/keyrings/rocm.gpg && \
      echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/rocm.gpg] https://repo.radeon.com/rocm/apt/$ROCM_VERSION jammy main" > /etc/apt/sources.list.d/rocm.list && \
      echo "Package: *\nPin: release o=repo.radeon.com\nPin-Priority: 600" > /etc/apt/preferences.d/rocm-pin-600 && \
      apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rocm-hip-runtime-dev && \
      echo "/opt/rocm/lib" > /etc/ld.so.conf.d/rocm.conf && \
      ldconfig \
    ; fi

COPY . /code

ARG TARGETVARIANT

# ROCm is only used on x86-64 since they don't have other packages
RUN \
    if [ $BUILDARCH != "arm64" ] && [ $TARGETARCH = "arm64" ]; then \
      export RUSTFLAGS="$RUSTFLAGS -C linker=aarch64-linux-gnu-gcc" \
    ; fi && \
    if [ $BUILDARCH != "riscv64" ] && [ $TARGETARCH = "riscv64" ]; then \
      export RUSTFLAGS="$RUSTFLAGS -C linker=riscv64-linux-gnu-gcc" \
    ; fi && \
    if [ $TARGETARCH = "amd64" ] && [ "$RUSTFLAGS" = "" ]; then \
      case "$TARGETVARIANT" in \
        # x86-64-v2 with AES-NI
        "v2") export RUSTFLAGS="-C target-cpu=x86-64-v2" ;; \
        # x86-64-v3 with AES-NI
        "v3") export RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes" ;; \
        # v4 is compiled for Zen 4+
        "v4") export RUSTFLAGS="-C target-cpu=znver4" ;; \
        # Default build is for Skylake
        *) export RUSTFLAGS="-C target-cpu=skylake" ;; \
      esac \
    ; fi && \
    if [ $BUILDARCH != "amd64" ] && [ $TARGETARCH = "amd64" ]; then \
      export RUSTFLAGS="$RUSTFLAGS -C linker=x86_64-linux-gnu-gcc" \
    ; fi && \
    export PATH=/usr/local/cuda/bin${PATH:+:${PATH}} && \
    RUSTC_TARGET_ARCH=$(echo $TARGETARCH | sed "s/amd64/x86_64/g" | sed "s/arm64/aarch64/g" | sed "s/riscv64/riscv64gc/g") && \
    if [ $BUILDARCH = "amd64" ] && [ $TARGETARCH = "amd64" ]; then \
      /root/.cargo/bin/cargo -Zgitoxide -Zgit build \
          --locked \
          -Z build-std \
          --profile $PROFILE \
          --bin subspace-farmer \
          --features rocm \
          --target $RUSTC_TARGET_ARCH-unknown-linux-gnu && \
      mv target/*/*/subspace-farmer subspace-farmer-rocm \
    ; fi && \
    if [ $(which nvcc) ]; then \
      /root/.cargo/bin/cargo -Zgitoxide -Zgit build \
          --locked \
          -Z build-std \
          --profile $PROFILE \
          --bin subspace-farmer \
          --features cuda \
          --target $RUSTC_TARGET_ARCH-unknown-linux-gnu \
    ; else \
      /root/.cargo/bin/cargo -Zgitoxide -Zgit build \
          --locked \
          -Z build-std \
          --profile $PROFILE \
          --bin subspace-farmer \
          --target $RUSTC_TARGET_ARCH-unknown-linux-gnu \
    ; fi && \
    mv target/*/*/subspace-farmer subspace-farmer && \
    rm -rf target

FROM ubuntu:22.04

ARG BUILDARCH
ARG TARGETARCH

# Next block is for ROCm support
# ROCm is only used on x86-64 since they don't have other packages
ARG ROCM_VERSION=6.2.2
RUN \
    if [ "$BUILDARCH/$TARGETARCH" = "amd64/amd64" ]; then \
      apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates gpg && \
      mkdir -p --mode=0755 /etc/apt/keyrings && \
      curl -L https://repo.radeon.com/rocm/rocm.gpg.key | gpg --dearmor > /etc/apt/keyrings/rocm.gpg && \
      echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/rocm.gpg] https://repo.radeon.com/rocm/apt/$ROCM_VERSION jammy main" > /etc/apt/sources.list.d/rocm.list && \
      echo "Package: *\nPin: release o=repo.radeon.com\nPin-Priority: 600" > /etc/apt/preferences.d/rocm-pin-600 && \
      apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends hip-runtime-amd && \
      DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge --autoremove curl ca-certificates gpg && \
      rm -rf /var/lib/apt/lists/* && \
      echo "/opt/rocm/lib" > /etc/ld.so.conf.d/rocm.conf && \
      ldconfig \
    ; fi

COPY --from=0 /code/subspace-farmer* /

RUN mkdir /var/subspace && chown nobody:nogroup /var/subspace

VOLUME /var/subspace

USER nobody:nogroup

ENTRYPOINT ["/subspace-farmer"]
