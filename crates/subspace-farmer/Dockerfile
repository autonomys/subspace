FROM ubuntu:20.04

WORKDIR /code

RUN \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
        llvm \
        clang \
        make \
        m4 && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly

COPY Cargo.lock /code/Cargo.lock
COPY Cargo.toml /code/Cargo.toml

# Hack to make Cargo download and cache dependencies
RUN \
    mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    /root/.cargo/bin/cargo build --release && \
    rm -rf src

COPY src /code/src

RUN \
    # TODO: Next line is a workaround for https://github.com/rust-lang/cargo/issues/7969
    touch src/main.rs && \
    /root/.cargo/bin/cargo test --release && \
    /root/.cargo/bin/cargo build --release && \
    mv target/release/subspace-farmer subspace-farmer && \
    rm -rf target

FROM ubuntu:20.04

COPY --from=0 /code/subspace-farmer /subspace-farmer

ENV SPARTAN_DIR=/var/spartan

RUN mkdir /var/spartan && chown nobody:nogroup /var/spartan

VOLUME /var/spartan

USER nobody:nogroup

ENTRYPOINT ["/subspace-farmer"]
