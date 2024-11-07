# This Dockerfile supports both native building and cross-compilation to aarch64 on x86-64
FROM --platform=$BUILDPLATFORM ubuntu:22.04

ARG RUSTC_VERSION=nightly-2024-10-22
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
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUSTC_VERSION && \
    /root/.cargo/bin/rustup target add wasm32-unknown-unknown

COPY Cargo.lock /code/Cargo.lock
COPY Cargo.toml /code/Cargo.toml
COPY rust-toolchain.toml /code/rust-toolchain.toml

COPY crates /code/crates
COPY domains /code/domains
COPY shared /code/shared
COPY test /code/test

# Up until this line all Rust images in this repo should be the same to share the same layers

ARG SUBSTRATE_CLI_GIT_COMMIT_HASH
ARG TARGETVARIANT

RUN \
    if [ $BUILDARCH != "arm64" ] && [ $TARGETARCH = "arm64" ]; then \
      export RUSTFLAGS="$RUSTFLAGS -C linker=aarch64-linux-gnu-gcc" \
    ; fi && \
    if [ $BUILDARCH != "riscv64" ] && [ $TARGETARCH = "riscv64" ]; then \
      export RUSTFLAGS="$RUSTFLAGS -C linker=riscv64-linux-gnu-gcc" \
    ; fi && \
    if [ $TARGETARCH = "amd64" ] && [ "$RUSTFLAGS" = ""]; then \
      case "$TARGETVARIANT" in \
        # x86-64-v2 with AES-NI
        "v2") export RUSTFLAGS="-C target-cpu=x86-64-v2 -C target-feature=+aes" ;; \
        # x86-64-v3 with AES-NI
        "v3") export RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes" ;; \
        # v4 is compiled for Zen 4+
        "v4") export RUSTFLAGS="-C target-cpu=znver4" ;; \
        # Default build is for Skylake
        *) export RUSTFLAGS="-C target-cpu=skylake" ;; \
      esac \
    ; fi && \
    RUSTC_TARGET_ARCH=$(echo $TARGETARCH | sed "s/amd64/x86_64/g" | sed "s/arm64/aarch64/g" | sed "s/riscv64/riscv64gc/g") && \
    /root/.cargo/bin/cargo -Zgitoxide -Zgit build \
        --locked \
        -Z build-std \
        --profile $PROFILE \
        --bin subspace-node \
        --target $RUSTC_TARGET_ARCH-unknown-linux-gnu && \
    mv target/*/*/subspace-node subspace-node && \
    rm -rf target

FROM ubuntu:22.04

RUN \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

HEALTHCHECK CMD curl -v http://localhost:9944/health

COPY --from=0 /code/subspace-node /subspace-node

RUN mkdir /var/subspace && chown nobody:nogroup /var/subspace

VOLUME /var/subspace

USER nobody:nogroup

ENTRYPOINT ["/subspace-node"]
