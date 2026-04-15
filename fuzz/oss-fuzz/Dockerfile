# OSS-Fuzz build image for latticearc.
#
# Consumed by google/oss-fuzz infrastructure. The base image ships a
# nightly rustc, cargo-fuzz, and the LLVM toolchain configured for
# libFuzzer + sanitizers. Our job is just to clone the repo and point
# OSS-Fuzz at our `build.sh` entrypoint.
#
# To integrate with upstream OSS-Fuzz, file a PR to
# https://github.com/google/oss-fuzz adding `projects/latticearc/`
# containing this Dockerfile, `project.yaml`, and `build.sh`.

FROM gcr.io/oss-fuzz-base/base-builder-rust

# CMake, a C/C++ toolchain, and Go are required to build aws-lc-rs
# (FIPS-validated C codebase) from source. The base image already has
# these but we list them explicitly so the Dockerfile stays honest if
# the base ever thins down.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake \
        golang-go \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Clone the latticearc repo at the ref OSS-Fuzz is building (default
# main). `--recurse-submodules` is not strictly needed for Layer 1
# (apache_repo is self-contained) but is cheap to specify.
RUN git clone --depth 1 https://github.com/LatticeArc/latticearc $SRC/latticearc

WORKDIR $SRC/latticearc

COPY build.sh $SRC/
